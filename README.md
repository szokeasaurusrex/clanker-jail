# clanker-jail

`clanker-jail` runs the Pi coding agent under a host-native macOS filesystem jail.

The default model is:

- current directory: read/write, with the same path inside and outside the jail
- fake home: read/write, persisted at `~/Library/Application Support/clanker-jail/home`
- temp: read/write, fresh per run under `/tmp`
- network: unrestricted
- environment: deny-by-default, with no API keys or credential variables inherited

This is intended to limit prompt-injection and agent-error blast radius by preventing the agent from reading host secrets in the first place. It is not VM-grade isolation.

## Usage

```sh
cargo run -- pi
```

Forward Pi arguments after `--`:

```sh
cargo run -- pi -- --model gpt-5.2
```

Run another command with the same sandbox environment Pi uses:

```sh
cargo run -- exec -- cargo test
```

Run the `@mariozechner/pi-ai` CLI login flow in the jail:

```sh
cargo run -- pi-login
```

Store a limited GitHub HTTPS token in the fake home:

```sh
cargo run -- github-login
```

Audit the generated sandbox profile:

```sh
cargo run -- print-profile
```

Validate core invariants:

```sh
cargo run -- doctor
```

## Options

- `--home <path>`: override the persistent fake home.
- `--tmp-parent <path>`: override the temp parent, default `/tmp`.
- `--keep-tmp`: keep the per-run temp dir after exit.
- `--allow-env <NAME>`: pass one host environment variable.
- `--allow-read <path>`: add an extra read-only path.
- `--allow-write <path>`: add an extra read/write path.
- `--no-refuse-broad-cwd`: allow launching from broad directories like the real home.

## Security Notes

- Do not launch from a directory containing secrets you do not want Pi to read.
- The launcher refuses obviously broad directories by default, including `/`, `/tmp`, `/Users`, and the real home directory.
- SSH agent sockets, GitHub tokens, cloud credentials, npm tokens, and model API keys are not inherited by default.
- GitHub auth is written to the fake home for HTTPS-based workflows. Prefer read-only or otherwise tightly scoped tokens.
- `sandbox-exec` is useful for damage-radius reduction but should not be treated as a hardened VM boundary.
