mod client;
mod commands;

// The wire protocol `client` speaks, from `cofferakd`'s library target
// (ADR 0004) — one shared definition, not a second copy.
use cofferakd::protocol;

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

use client::Client;
use cofferak_core::acl::{validate_id, Permission};
use cofferak_core::format::VaultLock;
use cofferak_core::seal::HostSeal;
use commands::audit::{format_audit_entry, run_audit_tail};
use commands::enroll::{run_enroll_host_with_seal, run_enroll_service};
use commands::init::{current_host_seal, run_init_host, run_init_root};
use commands::recover::run_recover;
use commands::secrets::{run_get, run_list, run_rm, run_rotate_dek, run_set};

/// Exit with a usage error unless `id` is a valid host/service id
/// (`acl::validate_id`): ids become file paths and OS credential names.
fn require_valid_id(kind: &str, id: &str) {
    if let Err(e) = validate_id(kind, id) {
        eprintln!("cofferak: {e}");
        std::process::exit(2);
    }
}

/// Run a vault admin command (anything that reads-modifies-writes
/// `vault.cofferak`) under the vault's exclusive lock — the same lock the
/// daemon takes before persisting a `set`/`rm` (ADR 0010) — so the two can
/// never interleave and drop each other's changes. Afterwards, hand any
/// files the command created back to the data directory's owner (see
/// [`match_data_dir_owner`]).
fn with_admin_lock<T>(data_dir: &Path, f: impl FnOnce() -> T) -> T {
    let lock = if data_dir.is_dir() {
        match VaultLock::acquire(&data_dir.join("vault.cofferak")) {
            Ok(lock) => Some(lock),
            Err(e) => {
                eprintln!(
                    "cofferak: could not lock the vault in {}: {e}",
                    data_dir.display()
                );
                std::process::exit(1);
            }
        }
    } else {
        // No data dir yet means no vault and nothing else writing one;
        // `init --root` creates it, every other command reports
        // "no vault found".
        None
    };
    let out = f();
    match_data_dir_owner(data_dir);
    drop(lock);
    out
}

/// On Linux, admin commands that seal or unseal host keys must run as root
/// (ADR 0009: `systemd-creds`' host secret is root-only), but the daemon
/// runs unprivileged as the data directory's owner (e.g. `cofferak`). So after
/// an admin command, any vault file not owned by the data directory's owner
/// is `lchown`ed to it. A no-op when the files already match (the common
/// non-root case); failures are ignored because a non-root caller can't
/// chown and doesn't need to.
#[cfg(unix)]
fn match_data_dir_owner(data_dir: &Path) {
    use std::os::unix::fs::MetadataExt;

    let Ok(dir_meta) = std::fs::metadata(data_dir) else {
        return;
    };
    let (uid, gid) = (dir_meta.uid(), dir_meta.gid());
    let mut paths = vec![
        data_dir.join("vault.cofferak"),
        data_dir.join("vault.cofferak.lock"),
        data_dir.join("meta.json"),
        data_dir.join("hosts"),
    ];
    if let Ok(entries) = std::fs::read_dir(data_dir.join("hosts")) {
        paths.extend(entries.flatten().map(|e| e.path()));
    }
    for path in paths {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.uid() != uid || meta.gid() != gid {
            let _ = std::os::unix::fs::lchown(&path, Some(uid), Some(gid));
        }
    }
}

#[cfg(not(unix))]
fn match_data_dir_owner(_data_dir: &Path) {}

/// `cofferak-cli`: administer a cofferak vault (init, enroll, ...).
#[derive(Parser)]
#[command(name = "cofferak-cli", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a vault (`--root`) or enroll this host into one
    /// (`--host <id>`).
    Init(InitArgs),
    /// Enroll an additional host into a vault that already has one.
    EnrollHost(EnrollHostArgs),
    /// Enroll a service, printing its one-time access token.
    EnrollService(EnrollServiceArgs),
    /// Set a secret's value (over the daemon's Unix socket).
    Set(SetArgs),
    /// Get a secret's value (over the daemon's Unix socket).
    Get(GetArgs),
    /// Remove a secret (over the daemon's Unix socket).
    Rm(RmArgs),
    /// List secret paths under a prefix (over the daemon's Unix socket).
    List(ListArgs),
    /// Rotate the vault's DEK (operates on `vault.cofferak` directly, not
    /// over the socket).
    RotateDek(RotateDekArgs),
    /// Disaster recovery: enroll a new host using the offline root
    /// private key, bypassing every enrolled host's own sealed blob.
    Recover(RecoverArgs),
    /// Inspect the daemon's audit log (local, offline — not a request over
    /// the socket).
    Audit(AuditArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Create a brand-new vault with a fresh root keypair.
    #[arg(long, conflicts_with = "host")]
    root: bool,

    /// Enroll this host (identified by `<id>`) into an existing vault.
    #[arg(long, value_name = "ID")]
    host: Option<String>,

    /// Vault data directory. Defaults to the platform data dir, or
    /// `$COFFERAK_DATA_DIR` if set.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args)]
struct EnrollHostArgs {
    /// The new host's id to enroll.
    new_host_id: String,

    /// The id of an already-enrolled host on this machine, whose own
    /// sealed key is used to recover the vault DEK before re-wrapping it
    /// for `new_host_id`.
    #[arg(long = "this-host", value_name = "ID")]
    this_host_id: String,

    /// Vault data directory. Defaults to the platform data dir, or
    /// `$COFFERAK_DATA_DIR` if set.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args)]
struct EnrollServiceArgs {
    /// The new service's id.
    service_id: String,

    /// Comma-separated list of path prefixes this service's token is
    /// scoped to.
    #[arg(long = "paths", value_name = "CSV")]
    paths: String,

    /// Access level granted over `--paths`.
    #[arg(long = "perm", value_enum)]
    perm: PermArg,

    /// Vault data directory. Defaults to the platform data dir, or
    /// `$COFFERAK_DATA_DIR` if set.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args)]
struct SetArgs {
    /// Secret path to write.
    path: String,
    /// Value to store, taken as raw UTF-8 bytes of this argument.
    value: String,
    /// Service access token (hex-encoded secret). Defaults to
    /// `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN")]
    token: String,
    /// Daemon Unix socket path. Defaults to the platform socket path, or
    /// `$COFFERAK_SOCKET` if set.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct GetArgs {
    /// Secret path to read.
    path: String,
    /// Service access token (hex-encoded secret). Defaults to
    /// `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN")]
    token: String,
    /// Daemon Unix socket path. Defaults to the platform socket path, or
    /// `$COFFERAK_SOCKET` if set.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct RmArgs {
    /// Secret path to remove.
    path: String,
    /// Service access token (hex-encoded secret). Defaults to
    /// `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN")]
    token: String,
    /// Daemon Unix socket path. Defaults to the platform socket path, or
    /// `$COFFERAK_SOCKET` if set.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct ListArgs {
    /// Path prefix to list. Defaults to the empty string (which the
    /// daemon's ACL check rejects for every token, since a token's
    /// granted prefixes are always non-empty) — pass an explicit prefix
    /// under your token's grant.
    #[arg(default_value = "")]
    prefix: String,
    /// Service access token (hex-encoded secret). Defaults to
    /// `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN")]
    token: String,
    /// Daemon Unix socket path. Defaults to the platform socket path, or
    /// `$COFFERAK_SOCKET` if set.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct RotateDekArgs {
    /// Comma-separated list of already-enrolled host ids to re-wrap the
    /// fresh DEK for. Must include at least one host enrolled on this
    /// machine.
    #[arg(long = "hosts", value_name = "CSV")]
    hosts: String,

    /// Vault data directory. Defaults to the platform data dir, or
    /// `$COFFERAK_DATA_DIR` if set.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args)]
struct RecoverArgs {
    /// Path to a file holding the offline root private key (32 raw
    /// bytes), printed once by `init --root` for the operator to copy
    /// down.
    #[arg(long = "root-key", value_name = "PATH")]
    root_key: PathBuf,

    /// The new host's id to enroll via recovery.
    #[arg(long = "new-host", value_name = "ID")]
    new_host_id: String,

    /// Vault data directory. Defaults to the platform data dir, or
    /// `$COFFERAK_DATA_DIR` if set.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args)]
struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Print the last `--count` (default 20) audit log entries, in order.
    Tail(AuditTailArgs),
}

#[derive(Args)]
struct AuditTailArgs {
    /// Number of most-recent entries to print.
    #[arg(long = "count", value_name = "N", default_value_t = 20)]
    count: usize,

    /// Vault data directory. Defaults to the platform data dir, or
    /// `$COFFERAK_DATA_DIR` if set. The audit log is read from
    /// `<data_dir>/audit.jsonl`.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

/// CLI-facing spelling of [`Permission`] (`ro`/`rw`), converted with
/// [`PermArg::into_permission`].
#[derive(Clone, Copy, ValueEnum)]
enum PermArg {
    Ro,
    Rw,
}

impl PermArg {
    fn into_permission(self) -> Permission {
        match self {
            PermArg::Ro => Permission::Read,
            PermArg::Rw => Permission::ReadWrite,
        }
    }
}

/// Default data directory on Linux, used unless `$COFFERAK_DATA_DIR` or
/// `--data-dir` is set.
#[cfg(target_os = "linux")]
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/cofferak")
}

/// Default data directory on macOS, used unless `$COFFERAK_DATA_DIR` or
/// `--data-dir` is set.
#[cfg(target_os = "macos")]
fn default_data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    PathBuf::from(home).join("Library/Application Support/cofferak")
}

fn resolve_data_dir(cli_data_dir: Option<PathBuf>) -> PathBuf {
    cli_data_dir
        .or_else(|| std::env::var_os("COFFERAK_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(default_data_dir)
}

/// Default Unix socket path on Linux, used unless `$COFFERAK_SOCKET` or
/// `--socket` is set. Mirrors `cofferakd`'s own default.
#[cfg(target_os = "linux")]
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/cofferak/cofferakd.sock")
}

/// Default Unix socket path on macOS, used unless `$COFFERAK_SOCKET` or
/// `--socket` is set. Mirrors `cofferakd`'s own default.
#[cfg(target_os = "macos")]
fn default_socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    PathBuf::from(home).join("Library/Application Support/cofferak/cofferakd.sock")
}

fn resolve_socket_path(cli_socket: Option<PathBuf>) -> PathBuf {
    cli_socket
        .or_else(|| std::env::var_os("COFFERAK_SOCKET").map(PathBuf::from))
        .unwrap_or_else(default_socket_path)
}

/// Connect to the daemon at `socket`, or print a clear error and exit.
fn connect_or_exit(socket: &std::path::Path) -> Client {
    Client::connect(socket).unwrap_or_else(|e| {
        eprintln!(
            "cofferak: could not connect to daemon at {}: {e}",
            socket.display()
        );
        std::process::exit(1);
    })
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => {
            let data_dir = resolve_data_dir(args.data_dir);

            match (args.root, args.host) {
                (true, None) => match with_admin_lock(&data_dir, || run_init_root(&data_dir)) {
                    Ok(fingerprint) => {
                        println!("vault initialized; root public key fingerprint: {fingerprint}");
                    }
                    Err(e) => {
                        eprintln!("cofferak: init --root failed: {e}");
                        std::process::exit(1);
                    }
                },
                (false, Some(host_id)) => {
                    require_valid_id("host", &host_id);
                    match with_admin_lock(&data_dir, || run_init_host(&data_dir, &host_id)) {
                        Ok(()) => {
                            println!("host '{host_id}' enrolled");
                        }
                        Err(e) => {
                            eprintln!("cofferak: init --host failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                (true, Some(_)) => {
                    // Unreachable in practice: clap's `conflicts_with`
                    // rejects `--root` together with `--host` before we get
                    // here, but handled explicitly rather than panicking.
                    eprintln!("cofferak: pass exactly one of --root or --host");
                    std::process::exit(2);
                }
                (false, None) => {
                    eprintln!("cofferak: pass one of --root or --host <id>");
                    std::process::exit(2);
                }
            }
        }
        Command::EnrollHost(args) => {
            let data_dir = resolve_data_dir(args.data_dir);
            require_valid_id("host", &args.this_host_id);
            require_valid_id("host", &args.new_host_id);

            let this_host_seal = current_host_seal(&args.this_host_id);
            let new_host_seal = current_host_seal(&args.new_host_id);

            match with_admin_lock(&data_dir, || {
                run_enroll_host_with_seal(
                    &data_dir,
                    &args.this_host_id,
                    &args.new_host_id,
                    this_host_seal.as_ref(),
                    new_host_seal.as_ref(),
                )
            }) {
                Ok(()) => {
                    println!("host '{}' enrolled", args.new_host_id);
                }
                Err(e) => {
                    eprintln!("cofferak: enroll-host failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::EnrollService(args) => {
            let data_dir = resolve_data_dir(args.data_dir);
            require_valid_id("service", &args.service_id);

            let prefixes: Vec<String> = args
                .paths
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            if prefixes.is_empty() {
                eprintln!("cofferak: --paths must list at least one non-empty path prefix");
                std::process::exit(2);
            }

            match with_admin_lock(&data_dir, || {
                run_enroll_service(
                    &data_dir,
                    &args.service_id,
                    prefixes,
                    args.perm.into_permission(),
                )
            }) {
                Ok(token) => {
                    // This is the one deliberate point where the CLI
                    // exposes a service's secret: the operator needs it to
                    // configure the consuming service. Never use `{:?}` on
                    // `AccessToken` (its derived `Debug` includes the raw
                    // secret) and never log the secret anywhere else.
                    let hex_secret: String =
                        token.secret.iter().map(|b| format!("{b:02x}")).collect();
                    println!(
                        "=== COFFERAK SERVICE ACCESS TOKEN for '{}' — copy this to the service now, it will not be shown again ===",
                        token.service_id
                    );
                    println!("{hex_secret}");
                    println!(
                        "============================================================================================="
                    );
                }
                Err(e) => {
                    eprintln!("cofferak: enroll-service failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Set(args) => {
            let client = connect_or_exit(&resolve_socket_path(args.socket));
            match run_set(&client, &args.token, &args.path, args.value.into_bytes()) {
                Ok(()) => println!("ok"),
                Err(e) => {
                    eprintln!("cofferak: set failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Get(args) => {
            let client = connect_or_exit(&resolve_socket_path(args.socket));
            match run_get(&client, &args.token, &args.path) {
                Ok(value) => {
                    use std::io::Write;
                    // The value is arbitrary bytes, not necessarily UTF-8
                    // text, so write it raw rather than assuming it can
                    // be formatted as a `String`.
                    let _ = std::io::stdout().write_all(&value);
                    let _ = std::io::stdout().write_all(b"\n");
                }
                Err(e) => {
                    eprintln!("cofferak: get failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Rm(args) => {
            let client = connect_or_exit(&resolve_socket_path(args.socket));
            match run_rm(&client, &args.token, &args.path) {
                Ok(()) => println!("removed"),
                Err(e) => {
                    eprintln!("cofferak: rm failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::List(args) => {
            let client = connect_or_exit(&resolve_socket_path(args.socket));
            match run_list(&client, &args.token, &args.prefix) {
                Ok(paths) => {
                    for path in paths {
                        println!("{path}");
                    }
                }
                Err(e) => {
                    eprintln!("cofferak: list failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::RotateDek(args) => {
            let data_dir = resolve_data_dir(args.data_dir);

            let hosts: Vec<(String, Box<dyn HostSeal>)> = args
                .hosts
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|id| {
                    require_valid_id("host", id);
                    let seal: Box<dyn HostSeal> = current_host_seal(id);
                    (id.to_string(), seal)
                })
                .collect();

            match with_admin_lock(&data_dir, || run_rotate_dek(&data_dir, &hosts)) {
                Ok(()) => println!("DEK rotated"),
                Err(e) => {
                    eprintln!("cofferak: rotate-dek failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Recover(args) => {
            let data_dir = resolve_data_dir(args.data_dir);
            require_valid_id("host", &args.new_host_id);
            let new_host_seal = current_host_seal(&args.new_host_id);

            match with_admin_lock(&data_dir, || {
                run_recover(
                    &data_dir,
                    &args.root_key,
                    &args.new_host_id,
                    new_host_seal.as_ref(),
                )
            }) {
                Ok(()) => {
                    println!("host '{}' recovered via offline root key", args.new_host_id);
                }
                Err(e) => {
                    eprintln!("cofferak: recover failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Audit(args) => match args.command {
            AuditCommand::Tail(tail_args) => {
                let data_dir = resolve_data_dir(tail_args.data_dir);
                let log_path = data_dir.join("audit.jsonl");

                match run_audit_tail(&log_path, tail_args.count) {
                    Ok(entries) => {
                        for entry in &entries {
                            println!("{}", format_audit_entry(entry));
                        }
                    }
                    Err(e) => {
                        eprintln!("cofferak: audit tail failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },
    }
}
