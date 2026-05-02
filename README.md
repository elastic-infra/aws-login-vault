# aws-login-vault

A Go reimplementation of AWS CLI v2's `aws login` (Management Console authentication). It persists the temporary credentials in the **macOS Keychain** so that the AWS CLI / SDKs can consume them transparently via `credential_process`.

## Features

- **SAME_DEVICE flow**: PKCE + DPoP + a local callback server + automatic browser launch
- **Dedicated Keychain**: credentials are isolated in `~/Library/Keychains/aws-login-vault.keychain-db` (separate from the login keychain)
- **Automatic refresh**: `export` refreshes the token automatically when fewer than 60 seconds remain (the same DPoP key is reused)
- **AssumeRole**: `export --role <arn>` caches the STS AssumeRole result. `source_identity` is opt-in
- **auto-login (opt-in)**: `--auto-login` opens the browser automatically when the profile is unauthenticated (rejected over SSH)
- **credential_process compatible**: emits AWS credential_process v1 protocol JSON on stdout
- **Concurrency safe**: a per-profile file lock prevents token races when `aws` is invoked in parallel

## Supported platforms

- **macOS only** (Linux / Windows planned)
- Go 1.25+ (build time)

## Install

### From source

```bash
go install github.com/hkobayash/aws-login-vault/cmd/aws-login-vault@latest
```

### Binary (tagged release)

Download `aws-login-vault_<version>_darwin_<arch>.tar.gz` from GitHub Releases and place `aws-login-vault` somewhere on your `$PATH`.

## Usage

### First login

```bash
aws-login-vault login --profile dev --region us-east-1
```

A browser opens and shows the AWS Sign-In page. After authentication, the temporary credentials are stored in the Keychain (the first run prompts for the keychain password and an Always Allow dialog).

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
| `login` | Run the SAME_DEVICE flow and store credentials in the Keychain. Overwrites unconditionally when `sub` matches an existing session; `--force` is required on mismatch |
| `logout` | Remove the profile's login_session and every cached assumed-role entry tied to it from the Keychain |
| `list` | List stored profiles |
| `export` | Print credential_process JSON / shell env on stdout. Refreshes before expiry; `--role` triggers AssumeRole |
| `show` | Inspect stored entries (secrets are masked; `--reveal` prints them in plain text) |

### `export` options

| Flag | Meaning | Default |
|---|---|---|
| `--profile` | Profile key in the Keychain | `default` |
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

`export --role` results are cached in the Keychain under the key `assumed/<profile>/<sha256(role-arn)>[/<source-identity>]`. AssumeRole is rerun once fewer than 5 minutes remain (the aws-vault style strategy). `logout` also drops every assumed entry tied to the profile.

## Inspecting the Keychain

```bash
# List all entries
security dump-keychain ~/Library/Keychains/aws-login-vault.keychain-db | grep aws-login-vault

# A specific profile
security find-generic-password -s aws-login-vault -a profile/default ~/Library/Keychains/aws-login-vault.keychain-db

# Wipe everything
security delete-keychain ~/Library/Keychains/aws-login-vault.keychain-db
```

## Limitations / known issues

- **macOS only**: the Keychain integration calls the Security framework via cgo. Linux / Windows support is future work
- **Lifetime of temporary credentials**: the AWS Sign-In API's `ExpiresIn` is at most 900 seconds (15 minutes). The refresh path extends the effective lifetime
- **DPoP private key**: the same key is reused throughout the entire refresh lifetime (`cnf.jkt` binding). Discard it with `logout` if it is exposed
- **CROSS_DEVICE flow not implemented**: usage over SSH is unsupported. Log in locally and ferry the credentials with scp etc.

## License

Not set (intended for internal use).
