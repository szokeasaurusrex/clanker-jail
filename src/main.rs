use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};

const APP_NAME: &str = "clanker-jail";

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pi(command) => {
            let context = JailContext::new(command.options)?;
            context.refuse_broad_cwd()?;
            context.prepare()?;
            context.run_sandboxed("pi", &command.args)
        }
        Commands::PiLogin(mut command) => {
            let context = JailContext::new(command.options)?;
            context.refuse_broad_cwd()?;
            context.prepare()?;
            if command.args.is_empty() {
                command.args.push("login".to_string());
            }
            command.args.insert(0, "@mariozechner/pi-ai".to_string());
            context.run_sandboxed("npx", &command.args)
        }
        Commands::GithubLogin(options) => {
            let context = JailContext::new(options)?;
            context.prepare()?;
            context.github_login()
        }
        Commands::Doctor(options) => {
            let context = JailContext::new(options)?;
            context.prepare()?;
            context.doctor()
        }
        Commands::PrintProfile(options) => {
            let context = JailContext::new(options)?;
            context.prepare()?;
            println!("{}", context.profile()?);
            context.cleanup_temp();
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
    /// Launch @mariozechner/pi-ai's CLI login flow in the jail.
    PiLogin(PiCommand),
    /// Store a limited GitHub HTTPS token in the fake home.
    GithubLogin(JailOptions),
    /// Validate core sandbox invariants.
    Doctor(JailOptions),
    /// Print the generated sandbox-exec profile.
    PrintProfile(JailOptions),
}

#[derive(Args, Debug)]
struct PiCommand {
    #[command(flatten)]
    options: JailOptions,
    /// Arguments forwarded to pi after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
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

    fn run_sandboxed(&self, program: &str, args: &[String]) -> Result<()> {
        let profile_path = self.write_profile()?;
        let program_path = find_executable(program)?;

        let mut command = Command::new("sandbox-exec");
        command
            .arg("-f")
            .arg(&profile_path)
            .arg("--")
            .arg(program_path)
            .args(args)
            .current_dir(&self.cwd)
            .env_clear()
            .envs(self.safe_env())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = command.status().context("failed to launch sandbox-exec")?;

        self.cleanup_temp();
        let _ = fs::remove_file(profile_path);

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
node -e 'if (process.stdin.isTTY) {{ process.stdin.setRawMode(true); process.stdin.setRawMode(false); }}'
node --version >/dev/null
pi --version >/dev/null
/usr/bin/curl -sS -I -L --max-time 10 https://pi.dev >/dev/null
echo "doctor ok"
"#,
            shell_escape(&self.real_home),
            shell_escape(&self.real_home)
        );

        let args = vec!["-c".to_string(), script];
        self.run_sandboxed("/bin/sh", &args)
    }

    fn github_login(&self) -> Result<()> {
        let token = prompt_secret("GitHub token (input hidden): ")?;
        if token.trim().is_empty() {
            bail!("empty token");
        }

        let gh_config_dir = self.fake_home.join(".config/gh");
        fs::create_dir_all(&gh_config_dir).with_context(|| {
            format!(
                "failed to create GitHub config directory `{}`",
                gh_config_dir.display()
            )
        })?;
        fs::set_permissions(&gh_config_dir, fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to restrict GitHub config directory `{}`",
                    gh_config_dir.display()
                )
            },
        )?;

        let hosts_path = gh_config_dir.join("hosts.yml");
        let content = format!(
            "github.com:\n    oauth_token: {}\n    git_protocol: https\n    user: clanker-jail\n",
            token.trim()
        );
        write_secret_file(&hosts_path, &content)?;

        let git_credentials = self.fake_home.join(".git-credentials");
        write_secret_file(
            &git_credentials,
            &format!("https://x-access-token:{}@github.com\n", token.trim()),
        )?;

        let gitconfig = self.fake_home.join(".gitconfig");
        let gitconfig_content = format!(
            "[credential]\n\thelper = store --file={}\n[url \"https://github.com/\"]\n\tinsteadOf = git@github.com:\n",
            git_credentials.display()
        );
        write_secret_file(&gitconfig, &gitconfig_content)?;

        println!(
            "stored GitHub HTTPS credentials under fake home `{}`",
            self.fake_home.display()
        );
        println!("use a limited-scope token; jailed Git and gh will not use your host auth store");
        Ok(())
    }

    fn write_profile(&self) -> Result<PathBuf> {
        let path = self.tmp_dir.join("sandbox.sb");
        fs::write(&path, self.profile()?)
            .with_context(|| format!("failed to write sandbox profile `{}`", path.display()))?;
        Ok(path)
    }

    fn profile(&self) -> Result<String> {
        let mut read_paths = BTreeSet::new();
        let mut write_paths = BTreeSet::new();

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
            Path::new("/opt/homebrew"),
            Path::new("/etc/profile"),
            Path::new("/etc/paths"),
            Path::new("/etc/manpaths"),
            Path::new("/etc/paths.d"),
            Path::new("/etc/manpaths.d"),
            Path::new("/private/etc/ssl/openssl.cnf"),
            Path::new("/private/etc/ssl/cert.pem"),
        ] {
            if path.exists() {
                read_paths.insert(canonical_or_absolute(path)?);
            }
        }

        for executable in ["pi", "node", "npm", "npx", "git", "gh", "curl", "sh", "zsh"] {
            if let Ok(path) = find_executable(executable) {
                add_path_and_ancestors(&mut read_paths, &path)?;
            }
        }

        for path in &self.extra_read {
            read_paths.insert(canonical_or_absolute(path)?);
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

        let mut profile = String::new();
        profile.push_str("(version 1)\n");
        profile.push_str("(deny default)\n");
        profile.push_str("(allow process*)\n");
        profile.push_str("(allow signal (target self))\n");
        profile.push_str("(allow sysctl-read)\n");
        profile.push_str("(allow mach-lookup)\n");
        profile.push_str("(allow network*)\n");
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

    fn safe_env(&self) -> BTreeMap<String, OsString> {
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
        envs.insert("PI_TELEMETRY".to_string(), OsString::from("0"));
        envs
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

fn prompt_secret(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().context("failed to flush stdout")?;

    let _ = Command::new("stty").arg("-echo").status();
    let mut input = String::new();
    let result = io::stdin().read_line(&mut input);
    let _ = Command::new("stty").arg("echo").status();
    println!();

    result.context("failed to read token").map(|_| input)
}

fn write_secret_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("failed to write `{}`", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict `{}`", path.display()))?;
    Ok(())
}
