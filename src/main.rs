use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use git2::Repository;
use home::{cargo_home, rustup_home};

const APP_NAME: &str = "clanker-jail";

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pi(command) => {
            let context = JailContext::new(command.options)?;
            context.refuse_broad_cwd()?;
            context.prepare()?;
            context.run_sandboxed("pi", &command.args, None)
        }
        Commands::Exec(command) => {
            let context = JailContext::new(command.options)?;
            context.refuse_broad_cwd()?;
            context.prepare()?;
            let (program, args) = command
                .args
                .split_first()
                .ok_or_else(|| anyhow!("exec requires a command to run"))?;
            context.run_sandboxed(program, args, None)
        }
        Commands::PiLogin(mut command) => {
            let context = JailContext::new(command.options)?;
            context.refuse_broad_cwd()?;
            context.prepare()?;
            context.ensure_agent_dir()?;
            if command.args.is_empty() {
                command.args.push("login".to_string());
            }
            command.args.insert(0, "@mariozechner/pi-ai".to_string());
            context.run_sandboxed("npx", &command.args, Some(&context.agent_dir()))
        }
        Commands::GithubLogin(options) => {
            let context = JailContext::new(options)?;
            context.refuse_broad_cwd()?;
            context.prepare()?;
            context.ensure_agent_dir()?;
            let args = vec![
                "@mariozechner/pi-ai".to_string(),
                "login".to_string(),
                "github-copilot".to_string(),
            ];
            context.run_sandboxed("npx", &args, Some(&context.agent_dir()))
        }
        Commands::Doctor(options) => {
            let context = JailContext::new(options)?;
            context.prepare()?;
            context.doctor()
        }
        Commands::PrintProfile(options) => {
            let context = JailContext::new(options)?;
            context.prepare()?;
            let mut proxy = context.start_proxy()?;
            println!("{}", context.profile(proxy.addr)?);
            proxy.shutdown()?;
            context.cleanup_temp();
            Ok(())
        }
        Commands::AgentDir(options) => {
            let context = JailContext::new(options)?;
            context.ensure_agent_dir()?;
            println!("{}", context.agent_dir().display());
            Ok(())
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = APP_NAME,
    version,
    about = "Run Pi in a macOS filesystem jail",
    long_about = "Runs the Pi coding agent with a fake persistent home, a per-run temp directory, unrestricted network, and filesystem access limited to the current project plus explicit allowlists."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch Pi in the current directory.
    Pi(PiCommand),
    /// Run an arbitrary command in the current directory using Pi's sandbox environment.
    Exec(ExecCommand),
    /// Launch @mariozechner/pi-ai's CLI login flow in the jail.
    PiLogin(PiCommand),
    /// Store a limited GitHub HTTPS token in the fake home.
    GithubLogin(JailOptions),
    /// Validate core sandbox invariants.
    Doctor(JailOptions),
    /// Print the generated sandbox-exec profile.
    PrintProfile(JailOptions),
    /// Print the path to the persistent Pi agent directory.
    ///
    /// Useful for version-controlling your agent configuration:
    ///
    ///   cd $(clanker-jail agent-dir)
    AgentDir(JailOptions),
}

#[derive(Args, Debug)]
struct PiCommand {
    #[command(flatten)]
    options: JailOptions,
    /// Arguments forwarded to pi after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Args, Debug)]
struct ExecCommand {
    #[command(flatten)]
    options: JailOptions,
    /// Command and arguments to run after `--`.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Args, Debug, Default)]
struct JailOptions {
    /// Fake persistent home.
    #[arg(long)]
    home: Option<PathBuf>,
    /// Parent for per-run temp dirs.
    #[arg(long, default_value = "/tmp")]
    tmp_parent: Option<PathBuf>,
    /// Keep temp dir after exit.
    #[arg(long)]
    keep_tmp: bool,
    /// Pass one host environment variable.
    #[arg(long, value_parser = parse_env_name)]
    allow_env: Vec<String>,
    /// Add extra read-only path.
    #[arg(long)]
    allow_read: Vec<PathBuf>,
    /// Add extra read/write path.
    #[arg(long)]
    allow_write: Vec<PathBuf>,
    /// Allow launching from broad directories like HOME.
    #[arg(long)]
    no_refuse_broad_cwd: bool,
}

fn parse_env_name(name: &str) -> Result<String, String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(format!("invalid environment variable name `{name}`"));
    }
    Ok(name.to_string())
}

#[derive(Debug)]
struct JailContext {
    real_home: PathBuf,
    cwd: PathBuf,
    fake_home: PathBuf,
    tmp_dir: PathBuf,
    tty_path: Option<PathBuf>,
    keep_tmp: bool,
    allow_env: BTreeSet<String>,
    extra_read: Vec<PathBuf>,
    extra_write: Vec<PathBuf>,
    no_refuse_broad_cwd: bool,
    git_dirs: Vec<PathBuf>,
    detected_cargo_home: Option<PathBuf>,
    detected_rustup_home: Option<PathBuf>,
}

impl JailContext {
    fn new(config: JailOptions) -> Result<Self> {
        let real_home = real_home()?;
        let cwd = env::current_dir()
            .context("failed to read current directory")?
            .canonicalize()
            .context("failed to canonicalize current directory")?;
        let fake_home = match config.home {
            Some(path) => absolute_path(path)?,
            None => real_home.join("Library/Application Support/clanker-jail/home"),
        };
        let tmp_parent = match config.tmp_parent {
            Some(path) => absolute_path(path)?,
            None => PathBuf::from("/tmp"),
        };
        let tmp_dir = tmp_parent.join(format!(
            "clanker-jail.{}.{}",
            std::process::id(),
            now_millis()?
        ));
        let tty_path = current_tty();

        let git_dirs = detect_git_dirs(&cwd);
        let detected_cargo_home = cargo_home().ok();
        let detected_rustup_home = rustup_home().ok();

        Ok(Self {
            real_home,
            cwd,
            fake_home,
            tmp_dir,
            tty_path,
            keep_tmp: config.keep_tmp,
            allow_env: config.allow_env.into_iter().collect(),
            extra_read: config.allow_read,
            extra_write: config.allow_write,
            no_refuse_broad_cwd: config.no_refuse_broad_cwd,
            git_dirs,
            detected_cargo_home,
            detected_rustup_home,
        })
    }

    fn prepare(&self) -> Result<()> {
        fs::create_dir_all(&self.fake_home).with_context(|| {
            format!("failed to create fake home `{}`", self.fake_home.display())
        })?;
        fs::set_permissions(&self.fake_home, fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to restrict fake home permissions `{}`",
                    self.fake_home.display()
                )
            },
        )?;
        fs::create_dir_all(&self.tmp_dir).with_context(|| {
            format!(
                "failed to create temp directory `{}`",
                self.tmp_dir.display()
            )
        })?;
        fs::set_permissions(&self.tmp_dir, fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to restrict temp permissions `{}`",
                    self.tmp_dir.display()
                )
            },
        )?;
        self.ensure_agent_dir()?;
        Ok(())
    }

    fn agent_dir(&self) -> PathBuf {
        self.fake_home.join(".pi/agent")
    }

    fn ensure_agent_dir(&self) -> Result<()> {
        let agent_dir = self.agent_dir();
        fs::create_dir_all(&agent_dir).with_context(|| {
            format!("failed to create agent directory `{}`", agent_dir.display())
        })?;
        fs::set_permissions(&agent_dir, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to restrict agent directory permissions `{}`",
                agent_dir.display()
            )
        })?;
        Ok(())
    }

    fn refuse_broad_cwd(&self) -> Result<()> {
        if self.no_refuse_broad_cwd {
            return Ok(());
        }

        let broad_paths = [
            PathBuf::from("/"),
            PathBuf::from("/tmp"),
            PathBuf::from("/private/tmp"),
            PathBuf::from("/Users"),
            self.real_home.clone(),
        ];
        if broad_paths.iter().any(|path| path == &self.cwd) {
            bail!(
                "refusing to jail broad current directory `{}`; use --no-refuse-broad-cwd if intentional",
                self.cwd.display()
            );
        }
        Ok(())
    }

    fn run_sandboxed(
        &self,
        program: &str,
        args: &[String],
        current_dir: Option<&Path>,
    ) -> Result<()> {
        let program_path = find_executable(program)?;
        let mut proxy = self.start_proxy()?;
        let profile_path = self.write_profile_with_executable(&program_path, proxy.addr)?;

        let mut command = Command::new("sandbox-exec");
        command
            .arg("-f")
            .arg(&profile_path)
            .arg("--")
            .arg(program_path)
            .args(args)
            .current_dir(current_dir.unwrap_or(&self.cwd))
            .env_clear()
            .envs(self.safe_env(Some(proxy.addr)))
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = command.status().context("failed to launch sandbox-exec")?;

        let shutdown_result = proxy.shutdown();
        self.cleanup_temp();
        let _ = fs::remove_file(profile_path);
        shutdown_result?;

        match status.code() {
            Some(0) => Ok(()),
            Some(code) => std::process::exit(code),
            None => bail!("sandboxed process terminated by signal"),
        }
    }

    fn cleanup_temp(&self) {
        if !self.keep_tmp {
            let _ = fs::remove_dir_all(&self.tmp_dir);
        }
    }

    fn doctor(&self) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .context("failed to bind doctor localhost test server")?;
        let local_test_addr = listener
            .local_addr()
            .context("failed to read doctor localhost test server address")?;
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
            }
        });

        let script = format!(
            r#"set -eu
touch "$PWD/.clanker-jail-doctor-cwd"
rm "$PWD/.clanker-jail-doctor-cwd"
touch "$HOME/.clanker-jail-doctor-home"
rm "$HOME/.clanker-jail-doctor-home"
touch "$TMPDIR/.clanker-jail-doctor-tmp"
rm "$TMPDIR/.clanker-jail-doctor-tmp"
if ls "{}" >/dev/null 2>&1; then echo "FAIL real home is readable"; exit 20; fi
if ls "{}/.ssh" >/dev/null 2>&1; then echo "FAIL ~/.ssh is readable"; exit 21; fi
if printenv SSH_AUTH_SOCK >/dev/null 2>&1; then echo "FAIL SSH_AUTH_SOCK leaked"; exit 22; fi
if printenv GITHUB_TOKEN >/dev/null 2>&1; then echo "FAIL GITHUB_TOKEN leaked"; exit 23; fi
if [ -n "$PI_CODING_AGENT_DIR" ] && [ -f "$PI_CODING_AGENT_DIR/auth.json" ]; then :; fi
node -e 'if (process.stdin.isTTY) {{ process.stdin.setRawMode(true); process.stdin.setRawMode(false); }}'
node --version >/dev/null
pi --version >/dev/null
if command -v rg >/dev/null 2>&1; then rg --version >/dev/null; fi
git --version >/dev/null
xcrun --sdk macosx --show-sdk-path >/dev/null
if [ "${{NO_PROXY-unset}}" != "" ]; then echo "FAIL NO_PROXY is not empty"; exit 24; fi
/usr/bin/curl -sS -I -L --max-time 10 https://pi.dev >/dev/null
if /usr/bin/curl --noproxy '*' -sS --max-time 2 http://127.0.0.1:{} >/dev/null 2>&1; then echo "FAIL direct localhost access worked"; exit 25; fi
if /usr/bin/curl -sS --max-time 2 http://127.0.0.1:{} >/dev/null 2>&1; then echo "FAIL proxied localhost access worked"; exit 26; fi
echo "doctor ok"
"#,
            shell_escape(&self.real_home),
            shell_escape(&self.real_home),
            local_test_addr.port(),
            local_test_addr.port()
        );

        let args = vec!["-c".to_string(), script];
        self.run_sandboxed("/bin/sh", &args, None)
    }

    fn write_profile_with_executable(
        &self,
        executable: &Path,
        proxy_addr: SocketAddr,
    ) -> Result<PathBuf> {
        self.write_profile_with_extra_read_paths(&[executable], proxy_addr)
    }

    fn write_profile_with_extra_read_paths(
        &self,
        extra_read_paths: &[&Path],
        proxy_addr: SocketAddr,
    ) -> Result<PathBuf> {
        let path = self.tmp_dir.join("sandbox.sb");
        fs::write(
            &path,
            self.profile_with_extra_read_paths(extra_read_paths, proxy_addr)?,
        )
        .with_context(|| format!("failed to write sandbox profile `{}`", path.display()))?;
        Ok(path)
    }

    /// Builds the read and write path sets that make up the sandbox policy.
    fn collect_path_sets(
        &self,
        extra_read_paths: &[&Path],
    ) -> Result<(BTreeSet<PathBuf>, BTreeSet<PathBuf>)> {
        let mut read_paths: BTreeSet<PathBuf> = BTreeSet::new();
        let mut write_paths: BTreeSet<PathBuf> = BTreeSet::new();

        for path in [
            &self.cwd,
            &self.fake_home,
            &self.tmp_dir,
            Path::new("/bin"),
            Path::new("/sbin"),
            Path::new("/usr/bin"),
            Path::new("/usr/sbin"),
            Path::new("/usr/lib"),
            Path::new("/usr/libexec"),
            Path::new("/usr/share"),
            Path::new("/System/Library"),
            Path::new("/Library/Apple"),
            Path::new("/Library/Developer"),
            Path::new("/Applications/Xcode.app"),
            Path::new("/Applications/Xcode-beta.app"),
            // Homebrew executables often load dylibs through stable `opt`
            // symlinks (for example, ripgrep -> pcre2).  `find_executable`
            // adds the executable path, but dyld still needs read access to
            // the Homebrew package store and link farm.
            Path::new("/opt/homebrew/bin"),
            Path::new("/opt/homebrew/sbin"),
            Path::new("/opt/homebrew/opt"),
            Path::new("/opt/homebrew/Cellar"),
            Path::new("/opt/homebrew/etc"),
            Path::new("/usr/local/bin"),
            Path::new("/usr/local/sbin"),
            Path::new("/usr/local/opt"),
            Path::new("/usr/local/Cellar"),
            Path::new("/usr/local/etc"),
            Path::new("/etc/profile"),
            Path::new("/etc/paths"),
            Path::new("/etc/manpaths"),
            Path::new("/etc/paths.d"),
            Path::new("/etc/manpaths.d"),
            Path::new("/private/etc/ssl/openssl.cnf"),
            Path::new("/private/etc/ssl/cert.pem"),
            Path::new("/System/Volumes/Preboot/Cryptexes/OS"),
            Path::new("/dev/null"),
            Path::new("/dev/autofs_nowait"),
            Path::new("/Users/dani/.CFUserTextEncoding"),
            // Xcode records license acceptance in this root-owned preference file.
            // Without it, xcrun/cc report that agreements were not accepted.
            Path::new("/Library/Preferences/com.apple.dt.Xcode.plist"),
            Path::new("/Library/Preferences/com.apple.networkd.plist"),
            Path::new("/private/var/db/timezone/tz"),
        ] {
            if path.exists() {
                read_paths.insert(canonical_or_absolute(path)?);
            }
        }

        for executable in [
            "pi", "node", "npm", "npx", "git", "curl", "rg", "sh", "zsh", "rustup", "rustc",
            "cargo",
        ] {
            if let Ok(path) = find_executable(executable) {
                add_path_and_ancestors(&mut read_paths, &path)?;
            }
        }

        for path in &self.extra_read {
            read_paths.insert(canonical_or_absolute(path)?);
        }
        for path in extra_read_paths {
            add_path_and_ancestors(&mut read_paths, path)?;
        }

        // Some Apple developer tools, notably xcrun invoked by cc, write cache
        // files under Darwin's per-user temp/cache directories instead of the
        // TMPDIR value supplied to the sandboxed process.
        for name in ["DARWIN_USER_TEMP_DIR", "DARWIN_USER_CACHE_DIR"] {
            if let Some(path) = getconf_path(name) {
                let canonical = canonical_or_absolute(&path)?;
                read_paths.insert(canonical.clone());
                write_paths.insert(canonical);
            }
        }

        // The active cargo home (from CARGO_HOME env var, or ~/.cargo if unset) is
        // readable and writable so the agent can fetch and cache crates.
        if let Some(ref cargo_home) = self.detected_cargo_home {
            let canonical = canonical_or_absolute(cargo_home)?;
            read_paths.insert(canonical.clone());
            write_paths.insert(canonical);
        }

        // The rustup home is read-only: the agent reads toolchains but must not
        // modify the rustup installation.
        if let Some(ref rustup_home) = self.detected_rustup_home
            && let Ok(canonical) = canonical_or_absolute(rustup_home)
        {
            read_paths.insert(canonical);
        }

        // Git directories (.git or the worktree-specific + common dirs) are readable and
        // writable so git operations inside the jail work correctly.
        for dir in &self.git_dirs {
            if let Ok(canonical) = canonical_or_absolute(dir) {
                read_paths.insert(canonical.clone());
                write_paths.insert(canonical);
            }
        }

        for path in [&self.cwd, &self.fake_home, &self.tmp_dir] {
            let canonical = canonical_or_absolute(path)?;
            read_paths.insert(canonical.clone());
            write_paths.insert(canonical);
        }
        for path in &self.extra_write {
            let canonical = canonical_or_absolute(path)?;
            read_paths.insert(canonical.clone());
            write_paths.insert(canonical);
        }

        Ok((read_paths, write_paths))
    }

    fn profile(&self, proxy_addr: SocketAddr) -> Result<String> {
        self.profile_with_extra_read_paths(&[], proxy_addr)
    }

    fn profile_with_extra_read_paths(
        &self,
        extra_read_paths: &[&Path],
        proxy_addr: SocketAddr,
    ) -> Result<String> {
        let (read_paths, write_paths) = self.collect_path_sets(extra_read_paths)?;

        let mut profile = String::new();
        profile.push_str("(version 1)\n");
        profile.push_str("(deny default)\n");
        profile.push_str("(allow process*)\n");
        profile.push_str("(allow signal (target self))\n");
        profile.push_str("(allow sysctl-read)\n");
        profile.push_str("(allow mach-lookup)\n");
        profile.push_str("(deny network*)\n");
        writeln!(
            profile,
            "(allow network-outbound (remote ip \"localhost:{}\"))",
            proxy_addr.port()
        )
        .context("failed to build sandbox profile")?;
        profile.push_str("(allow file-read-metadata)\n");
        profile.push_str("(allow file-map-executable)\n");
        profile.push_str("(allow file-read*");
        profile.push_str("\n  (literal \"/\")");
        profile.push_str("\n  (literal \"/dev/tty\")");
        profile.push_str("\n  (regex #\"^/dev/tty.*$\")");
        for path in read_paths {
            write!(profile, "\n  (subpath \"{}\")", sandbox_escape(&path))
                .context("failed to build sandbox profile")?;
        }
        profile.push_str(")\n");
        profile.push_str("(allow file-ioctl");
        profile.push_str("\n  (literal \"/dev/tty\")");
        profile.push_str("\n  (regex #\"^/dev/tty.*$\")");
        profile.push_str(")\n");
        profile.push_str("(allow file-write*");
        for path in write_paths {
            write!(profile, "\n  (subpath \"{}\")", sandbox_escape(&path))
                .context("failed to build sandbox profile")?;
        }
        if let Some(tty_path) = &self.tty_path {
            write!(profile, "\n  (literal \"{}\")", sandbox_escape(tty_path))
                .context("failed to build sandbox profile")?;
        }
        profile.push_str("\n  (regex #\"^/dev/tty.*$\")");
        for path in [
            "/dev/null",
            "/dev/zero",
            "/dev/tty",
            "/dev/urandom",
            "/dev/random",
        ] {
            write!(profile, "\n  (literal \"{path}\")")
                .context("failed to build sandbox profile")?;
        }
        profile.push_str(")\n");
        Ok(profile)
    }

    fn start_proxy(&self) -> Result<EgressProxy> {
        EgressProxy::start(&self.tmp_dir)
    }

    fn safe_env(&self, proxy_addr: Option<SocketAddr>) -> BTreeMap<String, OsString> {
        let mut envs = BTreeMap::new();
        for name in [
            "PATH",
            "TERM",
            "COLORTERM",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "SHELL",
        ] {
            if let Some(value) = env::var_os(name) {
                envs.insert(name.to_string(), value);
            }
        }
        for name in &self.allow_env {
            if let Some(value) = env::var_os(name) {
                envs.insert(name.clone(), value);
            }
        }

        envs.insert("HOME".to_string(), self.fake_home.clone().into_os_string());
        envs.insert("TMPDIR".to_string(), self.tmp_dir.clone().into_os_string());
        envs.insert(
            "XDG_CONFIG_HOME".to_string(),
            self.fake_home.join(".config").into_os_string(),
        );
        envs.insert(
            "XDG_CACHE_HOME".to_string(),
            self.fake_home.join(".cache").into_os_string(),
        );
        envs.insert(
            "XDG_DATA_HOME".to_string(),
            self.fake_home.join(".local/share").into_os_string(),
        );
        envs.insert("SWIFT_DISABLE_SANDBOX".to_string(), OsString::from("1"));
        envs.insert(
            "SWIFTPM_CACHE_PATH".to_string(),
            self.fake_home
                .join(".cache/org.swift.swiftpm")
                .into_os_string(),
        );
        envs.insert(
            "NPM_CONFIG_USERCONFIG".to_string(),
            self.fake_home.join(".npmrc").into_os_string(),
        );
        envs.insert(
            "NPM_CONFIG_CACHE".to_string(),
            self.fake_home.join(".npm").into_os_string(),
        );
        envs.insert(
            "GH_CONFIG_DIR".to_string(),
            self.fake_home.join(".config/gh").into_os_string(),
        );
        envs.insert(
            "GIT_CONFIG_GLOBAL".to_string(),
            self.fake_home.join(".gitconfig").into_os_string(),
        );
        envs.insert("GIT_CONFIG_NOSYSTEM".to_string(), OsString::from("1"));
        envs.insert(
            "PI_CODING_AGENT_DIR".to_string(),
            self.agent_dir().into_os_string(),
        );
        envs.insert("PI_TELEMETRY".to_string(), OsString::from("0"));

        if let Some(addr) = proxy_addr {
            let proxy_url = format!("socks5h://{addr}");
            envs.insert("ALL_PROXY".to_string(), OsString::from(&proxy_url));
            envs.insert("HTTP_PROXY".to_string(), OsString::from(&proxy_url));
            envs.insert("HTTPS_PROXY".to_string(), OsString::from(&proxy_url));
            envs.insert("NO_PROXY".to_string(), OsString::new());
        }

        // Pin cargo and rustup to their detected homes so they do not resolve
        // relative to the fake HOME set above.
        if let Some(ref path) = self.detected_cargo_home {
            envs.insert("CARGO_HOME".to_string(), path.clone().into_os_string());
        }
        if let Some(ref path) = self.detected_rustup_home {
            envs.insert("RUSTUP_HOME".to_string(), path.clone().into_os_string());
        }

        envs
    }
}

#[derive(Debug)]
struct EgressProxy {
    child: Child,
    addr: SocketAddr,
    stdin: Option<ChildStdin>,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
    shutdown_started: bool,
}

impl EgressProxy {
    fn start(tmp_dir: &Path) -> Result<Self> {
        let binary = find_egress_proxy_binary().context("failed to locate clanker-egress-proxy")?;
        let stdout_log = tmp_dir.join("clanker-egress-proxy.stdout.log");
        let stderr_log = tmp_dir.join("clanker-egress-proxy.stderr.log");
        let stderr = File::create(&stderr_log)
            .with_context(|| format!("failed to create `{}`", stderr_log.display()))?;

        let mut child = Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .with_context(|| format!("failed to start `{}`", binary.display()))?;

        let stdout = child.stdout.take().ok_or_else(|| {
            anyhow!(
                "failed to capture clanker-egress-proxy stdout; stderr log: {}",
                stderr_log.display()
            )
        })?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).with_context(|| {
            format!(
                "failed to read clanker-egress-proxy startup line; stderr log: {}",
                stderr_log.display()
            )
        })?;
        if bytes == 0 {
            let _ = child.wait();
            bail!(
                "clanker-egress-proxy exited before reporting its address; stderr log: {}",
                stderr_log.display()
            );
        }
        let addr_text = line
            .trim()
            .strip_prefix("CLANKER_EGRESS_PROXY=")
            .ok_or_else(|| {
                anyhow!(
                    "invalid clanker-egress-proxy startup line `{}`",
                    line.trim()
                )
            })?;
        let addr: SocketAddr = addr_text
            .parse()
            .with_context(|| format!("invalid clanker-egress-proxy address `{addr_text}`"))?;

        let mut stdout_file = File::create(&stdout_log)
            .with_context(|| format!("failed to create `{}`", stdout_log.display()))?;
        thread::spawn(move || {
            let mut reader = reader;
            let _ = std::io::copy(&mut reader, &mut stdout_file);
        });

        let stdin = child.stdin.take();

        Ok(Self {
            child,
            addr,
            stdin,
            stdout_log,
            stderr_log,
            shutdown_started: false,
        })
    }

    fn shutdown(&mut self) -> Result<()> {
        if self.shutdown_started {
            return Ok(());
        }
        self.shutdown_started = true;
        if self
            .child
            .try_wait()
            .context("failed to poll egress proxy")?
            .is_some()
        {
            return Ok(());
        }

        drop(self.stdin.take());
        for _ in 0..20 {
            if self
                .child
                .try_wait()
                .context("failed to poll egress proxy")?
                .is_some()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }

        eprintln!(
            "forcing clanker-egress-proxy cleanup; stdout log: {}; stderr log: {}",
            self.stdout_log.display(),
            self.stderr_log.display()
        );
        self.child.kill().context("failed to kill egress proxy")?;
        self.child
            .wait()
            .context("failed to wait for egress proxy")?;
        Ok(())
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Returns the absolute paths of git directories relevant to `cwd` using
/// libgit2 (via the `git2` crate).
///
/// `repo.path()` gives the per-worktree git dir (e.g. `.git/worktrees/<name>`
/// for a linked worktree).  `repo.commondir()` gives the shared git dir (the
/// main `.git` that all worktrees share).  For a plain checkout the two paths
/// are identical and the duplicate is dropped.
///
/// Returns an empty vec if `cwd` is not inside a git repo.
fn detect_git_dirs(cwd: &Path) -> Vec<PathBuf> {
    let Ok(repo) = Repository::discover(cwd) else {
        return Vec::new();
    };

    let mut dirs: Vec<PathBuf> = Vec::new();
    for raw in [repo.path(), repo.commondir()] {
        // libgit2 always returns absolute paths here.
        let path = raw.to_path_buf();
        if !dirs.contains(&path) {
            dirs.push(path);
        }
    }
    dirs
}

fn find_egress_proxy_binary() -> Result<PathBuf> {
    if let Some(path) = env::var_os("CLANKER_EGRESS_PROXY_BIN") {
        return PathBuf::from(path)
            .canonicalize()
            .with_context(|| "failed to canonicalize CLANKER_EGRESS_PROXY_BIN".to_string());
    }

    if let Ok(current_exe) = env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let sibling = parent.join("clanker-egress-proxy");
        if sibling.exists() {
            return sibling
                .canonicalize()
                .with_context(|| format!("failed to canonicalize `{}`", sibling.display()));
        }
        if current_exe
            .file_name()
            .is_some_and(|name| name == "clanker-jail")
            && current_exe.to_string_lossy().contains("/target/")
            && let Some(manifest) = find_workspace_manifest()
        {
            let status = Command::new("cargo")
                .arg("build")
                .arg("--manifest-path")
                .arg(manifest)
                .arg("-p")
                .arg("clanker-egress-proxy")
                .status()
                .context("failed to build clanker-egress-proxy for development run")?;
            if status.success() && sibling.exists() {
                return sibling
                    .canonicalize()
                    .with_context(|| format!("failed to canonicalize `{}`", sibling.display()));
            }
        }
    }

    find_executable("clanker-egress-proxy")
}

fn find_workspace_manifest() -> Option<PathBuf> {
    let mut dir = env::current_dir().ok()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() && dir.join("crates/clanker-egress-proxy/Cargo.toml").exists() {
            return Some(manifest);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn find_executable(name: &str) -> Result<PathBuf> {
    let path = if name.contains('/') {
        PathBuf::from(name)
    } else {
        let output = Command::new("/usr/bin/which")
            .arg(name)
            .output()
            .with_context(|| format!("failed to locate `{name}`"))?;
        if !output.status.success() {
            bail!("could not find `{name}` in PATH");
        }
        PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
    };

    path.canonicalize()
        .with_context(|| format!("failed to canonicalize executable `{}`", path.display()))
}

fn getconf_path(name: &str) -> Option<PathBuf> {
    let output = Command::new("/usr/bin/getconf").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn add_path_and_ancestors(paths: &mut BTreeSet<PathBuf>, executable: &Path) -> Result<()> {
    paths.insert(canonical_or_absolute(executable)?);
    if let Some(parent) = executable.parent() {
        paths.insert(canonical_or_absolute(parent)?);
        if parent.starts_with("/Users")
            && parent.to_string_lossy().contains("/.nvm/")
            && let Some(nvm_root) = parent
                .ancestors()
                .find(|path| path.file_name().is_some_and(|name| name == ".nvm"))
        {
            paths.insert(canonical_or_absolute(nvm_root)?);
        }
    }
    Ok(())
}

fn real_home() -> Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
        .and_then(absolute_path)
}

fn absolute_path(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        env::current_dir()
            .context("failed to read current directory")
            .map(|cwd| cwd.join(path))
    }
}

fn canonical_or_absolute(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        path.canonicalize()
            .with_context(|| format!("failed to canonicalize `{}`", path.display()))
    } else {
        absolute_path(path.to_path_buf())
    }
}

fn current_tty() -> Option<PathBuf> {
    let output = Command::new("/usr/bin/tty").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path == "not a tty" || path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

fn now_millis() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_millis())
}

fn sandbox_escape(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn shell_escape(path: &Path) -> String {
    path.to_string_lossy().replace('"', "\\\"")
}
