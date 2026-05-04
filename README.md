# aws-login-vault

A Go reimplementation of AWS CLI v2's `aws login` (Management Console authentication). It persists the temporary credentials in the **OS secure store** (macOS Keychain / Linux SecretService / Pass / KeyCtl) so that the AWS CLI / SDKs can consume them transparently via `credential_process`. The basic flow is PKCE + DPoP + a local callback server; for use over SSH it also supports the CROSS_DEVICE flow (`--remote`).

## Features

- **SAME_DEVICE flow**: PKCE + DPoP + a local callback server + automatic browser launch
- **OS secure store integration**: macOS uses a dedicated Keychain; Linux picks automatically from SecretService (GNOME Keyring / KWallet) / Pass (gpg-agent) / KeyCtl (kernel keyring)
- **Automatic refresh**: `export` refreshes the token automatically when fewer than 60 seconds remain (the same DPoP key is reused)
- **AssumeRole**: `export --role <arn>` caches the STS AssumeRole result. `source_identity` is opt-in
- **auto-login (opt-in)**: `--auto-login` opens the browser automatically when the profile is unauthenticated (rejected over SSH)
- **credential_process compatible**: emits AWS credential_process v1 protocol JSON on stdout
- **Concurrency safe**: a per-profile file lock prevents token races when `aws` is invoked in parallel

## Supported platforms

- **macOS** (Keychain backend; cgo required)
- **Linux** (one of SecretService / Pass / KeyCtl; see prerequisites below)
- Go 1.26+ (build time)

## Install

### From source

```bash
go install github.com/hkobayash/aws-login-vault/cmd/aws-login-vault@latest
```

### Binary (tagged release)

Download the tar.gz that matches your OS / architecture from GitHub Releases:

```
aws-login-vault_<version>_darwin_amd64.tar.gz
aws-login-vault_<version>_darwin_arm64.tar.gz
aws-login-vault_<version>_linux_amd64.tar.gz
aws-login-vault_<version>_linux_arm64.tar.gz
```

Extract the archive and place `aws-login-vault` somewhere on your `$PATH`.

## Usage

### First login

```bash
aws-login-vault login --profile dev --region us-east-1
```

A browser opens and shows the AWS Sign-In page. After authentication, the temporary credentials are stored in the OS secure store.

- **macOS**: the first run prompts for the keychain password and an Always Allow dialog
- **Linux SecretService**: stored in the existing login keyring (GNOME / KDE)
- **Linux Pass**: creates `~/.password-store/aws-login-vault/profile/<name>.gpg`

### Logging in from a remote machine (over SSH)

In environments where the local browser cannot reach the callback server, use `--remote` (the CROSS_DEVICE flow):

```bash
# Inside the SSH session on the remote host
aws-login-vault login --remote --profile dev --region us-east-1
```

1. The CLI prints the authorize URL on stderr
2. Open that URL in a browser on your **local machine** and authenticate
3. Copy the verification code (a base64 string) shown in the browser after auth
4. Paste it into the terminal on the remote host and press Enter
5. Login succeeds and is persisted to the store

`--remote` requires interactive paste, so it cannot be used through `credential_process` (e.g. `export --auto-login`); only SAME_DEVICE works there. Automatic refresh on the remote host still works through the `export` path once the initial login is in place.

### `~/.aws/config`

```ini
[profile dev]
credential_process = aws-login-vault export --profile dev --format json
region = us-east-1

# Native AWS AssumeRole (lightest path when you do not need source_identity)
[profile dev-admin]
role_arn = arn:aws:iam::123456789012:role/Admin
source_profile = dev

# AssumeRole through aws-login-vault (use this when you need source_identity, etc.)
[profile dev-ops]
credential_process = aws-login-vault export --profile dev --role arn:aws:iam::123456789012:role/Ops --source-identity auto --format json
region = us-east-1
```

### Command reference

```
aws-login-vault login   [--profile NAME] [--region R] [--force]
aws-login-vault logout  [--profile NAME]
aws-login-vault list
aws-login-vault export  [--profile NAME] [--format json|env]
                        [--role ARN] [--role-session-name NAME]
                        [--source-identity auto|<val>] [--role-duration DUR]
                        [--auto-login]
aws-login-vault show    PROFILE [--reveal]
```

| Command | Role |
|---|---|
| `login` | Run the SAME_DEVICE flow and persist to the store. Overwrites unconditionally when `sub` matches an existing session; `--force` is required on mismatch |
| `logout` | Remove the profile's login_session and every cached assumed-role entry tied to it from the store |
| `list` | List stored profiles |
| `export` | Print credential_process JSON / shell env on stdout. Refreshes before expiry; `--role` triggers AssumeRole |
| `show` | Inspect stored entries (secrets are masked; `--reveal` prints them in plain text) |

### `export` options

| Flag | Meaning | Default |
|---|---|---|
| `--profile` | Profile key in the store | `default` |
| `--format` | `json` (credential_process v1) or `env` (`export AWS_…=`) | `json` |
| `--role` | Target role ARN for STS AssumeRole | (unset; specifying it switches to AssumeRole mode) |
| `--role-session-name` | Override RoleSessionName | derived from `sub` |
| `--source-identity` | `auto` (derived from `sub`) or any literal value | unset (SetSourceIdentity is not sent) |
| `--role-duration` | DurationSeconds for AssumeRole | 1h |
| `--auto-login` | Run login automatically when unauthenticated (rejected over SSH) | enable globally with `AWS_LOGIN_VAULT_AUTO_LOGIN=1` |

### auto-login

When `--auto-login` (or the environment variable `AWS_LOGIN_VAULT_AUTO_LOGIN=1`) is set, `export` attempts auto-login as follows:

```
$SSH_CONNECTION / $SSH_TTY is set → error (browser cannot reach a remote box)
otherwise                         → launch browser → wait for auth → emit creds
                                    if the browser fails to open, print the URL on stderr and exit 1
```

To honor the `credential_process` contract, **stdin is never read** (no interactive prompt).

### AssumeRole cache

`export --role` results are cached in the store under the key `assumed/<profile>/<sha256(role-arn)>[/<source-identity>]`. AssumeRole is rerun once fewer than 5 minutes remain (the aws-vault style strategy). `logout` also drops every assumed entry tied to the profile.

## Inspecting the store

### macOS (Keychain)

```bash
# File: ~/Library/Keychains/aws-login-vault.keychain-db
security dump-keychain ~/Library/Keychains/aws-login-vault.keychain-db | grep aws-login-vault
security find-generic-password -s aws-login-vault -a profile/default ~/Library/Keychains/aws-login-vault.keychain-db
security delete-keychain ~/Library/Keychains/aws-login-vault.keychain-db   # wipe everything
```

### Linux SecretService (GNOME Keyring / KWallet)

```bash
secret-tool lookup service aws-login-vault account profile/default
# GUI: inspect the "aws-login-vault" collection in Seahorse (GNOME) / KWalletManager (KDE)
```

### Linux Pass

```bash
pass list aws-login-vault
pass show aws-login-vault/profile/default
```

### Linux KeyCtl (session-scoped)

```bash
keyctl list @s   # list entries; reference individual ones by their numeric ID
```

## Linux prerequisites

### SecretService (recommended, desktop environments)

No extra setup is needed inside a GNOME / KDE session. It is used automatically when `gnome-keyring-daemon` or `kwalletd` is running.

### Pass (headless / over SSH)

Setup:

```bash
sudo apt install pass     # debian/ubuntu (or the equivalent for your distro)
gpg --gen-key             # generate a GPG key (if you do not have one)
pass init <gpg-key-id>    # initialize ~/.password-store
```

If gpg-agent prompts to unlock while `aws` invokes `credential_process`, the call hangs. Run `pass show <anything>` once beforehand to start the agent and warm its cache. Extending `default-cache-ttl` in `gpg-agent.conf` makes day-to-day operation easier:

```
# ~/.gnupg/gpg-agent.conf
default-cache-ttl 28800   # 8h
max-cache-ttl 28800
```

### KeyCtl

Session-scoped. Because entries vanish on reboot / logout, KeyCtl is treated as a fallback for `credential_process` after SecretService / Pass.

### Backend selection order

The `AllowedBackends` priority is: **SecretService → Pass → KeyCtl**. The first available one is picked. Switching explicitly currently requires killing the GUI session, removing pass's `~/.password-store`, etc. (a `--backend` flag is under consideration).

## Limitations / known issues

- **No Windows support**: a future WinCred backend is under consideration
- **Lifetime of temporary credentials**: the AWS Sign-In API's `ExpiresIn` is at most 900 seconds (15 minutes). The refresh path extends the effective lifetime
- **DPoP private key**: the same key is reused throughout the entire refresh lifetime (`cnf.jkt` binding). Discard it with `logout` if it is exposed

## License

Not set (intended for internal use).
