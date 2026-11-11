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
    /// Run the daemon in the foreground (same code as `cofferakd`).
    /// Configured by the COFFERAK_* environment variables. On macOS use
    /// this rather than `cofferakd`: the Keychain lets the `cofferak` binary
    /// read the host key it sealed without an authorization prompt.
    Daemon,
    /// Import a `.env` file: each `KEY=value` becomes `<prefix>/<KEY>`.
    ImportEnv(ImportEnvArgs),
    /// Write the variables under a prefix as a `.env` file.
    ExportEnv(ExportEnvArgs),
    /// Run a command with the secrets under one or more prefixes set as
    /// environment variables (no `.env` file on disk).
    Run(RunArgs),
    /// Export the whole vault (every secret and service token) as an
    /// encrypted, passphrase-protected bundle, to back up or move to
    /// another machine or OS.
    Export(ExportArgs),
    /// Import a bundle made by `export` (passphrase or peer transfer) into
    /// this vault.
    Import(ImportArgs),
    /// Print this coffer's public identity (created on first use), to give
    /// to another coffer that should be able to send you secrets.
    Identity(IdentityArgs),
    /// Manage trusted peer coffers (who may send you transfers, and whom
    /// you can export to with `export --to`).
    Peer(PeerArgs),
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
    /// Value to store, as the raw bytes of this argument. Convenient for
    /// non-sensitive tests only: a command-line argument is visible to
    /// other processes and lands in shell history. Prefer `--stdin` or
    /// `--from-file`.
    #[arg(conflicts_with_all = ["stdin", "from_file"], required_unless_present_any = ["stdin", "from_file"])]
    value: Option<String>,
    /// Read the value from standard input (exact bytes, up to EOF), e.g.
    /// `cofferak set app/KEY --stdin < secret.txt` or a hidden prompt.
    #[arg(long, conflicts_with = "from_file")]
    stdin: bool,
    /// Read the value from a file (exact bytes), e.g. an SSH private key.
    #[arg(long, value_name = "FILE")]
    from_file: Option<PathBuf>,
    /// Service access token (hex-encoded secret). Defaults to
    /// `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN", hide_env_values = true)]
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
    /// Write the value to this file (exact bytes, created with mode 0600)
    /// instead of standard output.
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,
    /// Service access token (hex-encoded secret). Defaults to
    /// `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN", hide_env_values = true)]
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
    #[arg(long, env = "COFFERAK_TOKEN", hide_env_values = true)]
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
    #[arg(long, env = "COFFERAK_TOKEN", hide_env_values = true)]
    token: String,
    /// Daemon Unix socket path. Defaults to the platform socket path, or
    /// `$COFFERAK_SOCKET` if set.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct ImportEnvArgs {
    /// The `.env` file to import (`-` reads standard input).
    file: PathBuf,
    /// Path prefix to store the variables under, e.g. `myapp/env`.
    #[arg(long)]
    prefix: String,
    /// Replace values that already exist (default: keep them, report them).
    #[arg(long)]
    overwrite: bool,
    /// Show what would be imported without writing anything.
    #[arg(long)]
    dry_run: bool,
    /// Service access token. Defaults to `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN", hide_env_values = true)]
    token: String,
    /// Daemon Unix socket path. Defaults to `$COFFERAK_SOCKET` / the platform path.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct ExportEnvArgs {
    /// Path prefix whose direct children to export, e.g. `myapp/env`.
    #[arg(long)]
    prefix: String,
    /// File to write (mode 0600), or `-` for standard output. The file
    /// holds plaintext secrets: prefer `cofferak run` where you can.
    #[arg(long, short = 'o', value_name = "FILE")]
    out: PathBuf,
    /// Overwrite the output file if it exists.
    #[arg(long)]
    force: bool,
    /// Service access token. Defaults to `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN", hide_env_values = true)]
    token: String,
    /// Daemon Unix socket path. Defaults to `$COFFERAK_SOCKET` / the platform path.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct RunArgs {
    /// Prefix whose direct children become environment variables
    /// (repeatable; later prefixes override earlier ones).
    #[arg(long, required = true)]
    prefix: Vec<String>,
    /// Pass COFFERAK_TOKEN on to the command (default: removed, so the
    /// command gets its secrets but not the token).
    #[arg(long)]
    keep_token: bool,
    /// Service access token. Defaults to `$COFFERAK_TOKEN` if set.
    #[arg(long, env = "COFFERAK_TOKEN", hide_env_values = true)]
    token: String,
    /// Daemon Unix socket path. Defaults to `$COFFERAK_SOCKET` / the platform path.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// The command to run, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Args)]
struct ExportArgs {
    /// Bundle file to write (mode 0600).
    #[arg(long, short = 'o', value_name = "FILE")]
    out: PathBuf,
    /// Encrypt for this trusted peer coffer (see `cofferak peer`) instead
    /// of with a passphrase. Only that coffer can import it, and it can
    /// verify the bundle came from this one.
    #[arg(long, value_name = "PEER")]
    to: Option<String>,
    /// Export only secrets under this prefix (repeatable). Default: all.
    #[arg(long, value_name = "PREFIX")]
    prefix: Vec<String>,
    /// Include service tokens even with --prefix (a whole-vault export
    /// always includes them).
    #[arg(long)]
    with_tokens: bool,
    /// Overwrite the bundle file if it exists.
    #[arg(long)]
    force: bool,
    /// Read the passphrase from this file (first line) instead of
    /// prompting. For automation; keep the file private.
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,
    /// Vault data directory. Defaults to `$COFFERAK_DATA_DIR` / the platform data dir.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args)]
struct ImportArgs {
    /// Bundle file made by `cofferak export`.
    file: PathBuf,
    /// Replace secrets and services that already exist (default: keep them).
    #[arg(long)]
    overwrite: bool,
    /// Show what would be imported without writing anything.
    #[arg(long)]
    dry_run: bool,
    /// Read the passphrase from this file (first line) instead of prompting.
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,
    /// For a peer transfer: accept it only if signed by this identity file
    /// (instead of requiring the sender to be a stored peer).
    #[arg(long, value_name = "IDENTITY_FILE")]
    from: Option<PathBuf>,
    /// Vault data directory. Defaults to `$COFFERAK_DATA_DIR` / the platform data dir.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args)]
struct IdentityArgs {
    /// Also write the identity to this file (to copy to the other coffer).
    #[arg(long, short = 'o', value_name = "FILE")]
    out: Option<PathBuf>,
    /// Vault data directory. Defaults to `$COFFERAK_DATA_DIR` / the platform data dir.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
}

#[derive(Args)]
struct PeerArgs {
    #[command(subcommand)]
    command: PeerCommand,
    /// Vault data directory. Defaults to `$COFFERAK_DATA_DIR` / the platform data dir.
    #[arg(long, value_name = "DIR", global = true)]
    data_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Trust another coffer: NAME and the identity file it gave you
    /// (`cofferak identity -o FILE` there; `-` reads standard input).
    Add {
        name: String,
        identity_file: PathBuf,
        /// Replace an existing peer with this name.
        #[arg(long)]
        replace: bool,
    },
    /// List trusted peers and their fingerprints.
    List,
    /// Stop trusting a peer.
    Rm { name: String },
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

/// Largest value `set` accepts. The wire protocol encodes bytes as a JSON
/// array (up to 4 characters per byte) inside a 16 MiB line, so 3 MiB
/// leaves headroom; secrets, keys and certificates are far smaller.
const MAX_SECRET_BYTES: usize = 3 * 1024 * 1024;

/// The value for `set`, from the positional argument, `--stdin` or
/// `--from-file`, held in zeroize-on-drop memory.
fn read_set_value(args: &SetArgs) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use std::io::Read;
    let bytes = if args.stdin {
        let mut buf = Vec::new();
        std::io::stdin()
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("reading standard input: {e}"))?;
        buf
    } else if let Some(path) = &args.from_file {
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.len() > MAX_SECRET_BYTES as u64 {
            return Err(format!(
                "{} is {} bytes; the maximum secret size is {MAX_SECRET_BYTES} bytes",
                path.display(),
                meta.len()
            ));
        }
        std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?
    } else {
        args.value.clone().unwrap_or_default().into_bytes()
    };
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(format!(
            "the maximum secret size is {MAX_SECRET_BYTES} bytes"
        ));
    }
    Ok(zeroize::Zeroizing::new(bytes))
}

/// Write a `get` result: to `output` (exact bytes, mode 0600) if given,
/// otherwise to stdout. On a terminal a trailing newline is added for
/// readability; when piped or redirected, the exact stored bytes are
/// written (so `cofferak get k | ssh-add -` gets the key byte for byte).
fn write_get_value(value: &[u8], output: Option<&Path>) -> std::io::Result<()> {
    use std::io::{IsTerminal, Write};
    if let Some(path) = output {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path)?;
        f.write_all(value)?;
        return f.sync_all();
    }
    let mut out = std::io::stdout().lock();
    out.write_all(value)?;
    if out.is_terminal() && !value.ends_with(b"\n") {
        out.write_all(b"\n")?;
    }
    out.flush()
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

/// Restore the default SIGPIPE action for normal CLI commands, so
/// `cofferak list | head -1` exits quietly like any Unix tool instead of
/// panicking on "Broken pipe". Not used for `cofferak daemon`: a server
/// must keep SIGPIPE ignored so a disconnecting client can't kill it.
fn default_sigpipe() {
    #[cfg(unix)]
    // SAFETY: setting a signal disposition to SIG_DFL at startup, before any
    // threads exist, has no memory-safety implications.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() {
    let cli = Cli::parse();
    if !matches!(cli.command, Command::Daemon) {
        default_sigpipe();
    }

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
            let value = read_set_value(&args).unwrap_or_else(|e| {
                eprintln!("cofferak: set failed: {e}");
                std::process::exit(1);
            });
            let client = connect_or_exit(&resolve_socket_path(args.socket));
            match run_set(&client, &args.token, &args.path, value.to_vec()) {
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
                    let value = zeroize::Zeroizing::new(value);
                    if let Err(e) = write_get_value(&value, args.output.as_deref()) {
                        eprintln!("cofferak: get failed: {e}");
                        std::process::exit(1);
                    }
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
        Command::Daemon => cofferakd::server::run(),
        Command::ImportEnv(args) => cmd_import_env(args),
        Command::ExportEnv(args) => cmd_export_env(args),
        Command::Run(args) => cmd_run(args),
        Command::Export(args) => cmd_export(args),
        Command::Import(args) => cmd_import(args),
        Command::Identity(args) => cmd_identity(args),
        Command::Peer(args) => cmd_peer(args),
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

fn fail(context: &str, e: impl std::fmt::Display) -> ! {
    eprintln!("cofferak: {context}: {e}");
    std::process::exit(1);
}

fn cmd_import_env(args: ImportEnvArgs) {
    let text = if args.file.as_os_str() == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .unwrap_or_else(|e| fail("import-env", format!("reading standard input: {e}")));
        zeroize::Zeroizing::new(s)
    } else {
        zeroize::Zeroizing::new(
            std::fs::read_to_string(&args.file)
                .unwrap_or_else(|e| fail("import-env", format!("{}: {e}", args.file.display()))),
        )
    };
    let client = connect_or_exit(&resolve_socket_path(args.socket));
    let r = commands::transfer::run_import_env(
        &client,
        &args.token,
        &args.prefix,
        &text,
        args.overwrite,
        args.dry_run,
    )
    .unwrap_or_else(|e| fail("import-env", e));
    let prefix = args.prefix.trim_end_matches('/');
    let verb = if args.dry_run {
        "would import"
    } else {
        "imported"
    };
    for k in &r.added {
        println!("  + {prefix}/{k}");
    }
    for k in &r.replaced {
        println!("  ~ {prefix}/{k} (replaced)");
    }
    for k in &r.skipped {
        println!("  = {prefix}/{k} (exists, kept; use --overwrite to replace)");
    }
    println!(
        "{verb} {} new, {} replaced, {} kept",
        r.added.len(),
        r.replaced.len(),
        r.skipped.len()
    );
    if !args.dry_run && !r.added.is_empty() {
        println!("check with `cofferak list {prefix}`, then delete the .env file");
    }
}

/// Write `bytes` to `path` with mode 0600, refusing to replace an
/// existing file unless `force`.
fn write_private(path: &Path, bytes: &[u8], force: bool) -> std::io::Result<()> {
    if path.exists() && !force {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists (use --force to overwrite)", path.display()),
        ));
    }
    cofferak_core::format::write_atomic(path, bytes)
}

fn cmd_export_env(args: ExportEnvArgs) {
    let client = connect_or_exit(&resolve_socket_path(args.socket));
    let (text, skipped) = commands::transfer::run_export_env(&client, &args.token, &args.prefix)
        .unwrap_or_else(|e| fail("export-env", e));
    for s in &skipped {
        eprintln!("cofferak: export-env: skipped {s}");
    }
    if args.out.as_os_str() == "-" {
        use std::io::Write;
        let _ = std::io::stdout().write_all(text.as_bytes());
        return;
    }
    write_private(&args.out, text.as_bytes(), args.force).unwrap_or_else(|e| fail("export-env", e));
    let n = text.lines().count();
    println!(
        "wrote {n} variables to {} (mode 0600; it contains plaintext secrets)",
        args.out.display()
    );
}

fn cmd_run(args: RunArgs) {
    let client = connect_or_exit(&resolve_socket_path(args.socket));
    let (vars, skipped) = commands::transfer::collect_env(&client, &args.token, &args.prefix)
        .unwrap_or_else(|e| fail("run", e));
    for s in &skipped {
        eprintln!("cofferak: run: skipped {s}");
    }
    let mut cmd = std::process::Command::new(&args.command[0]);
    cmd.args(&args.command[1..]);
    if !args.keep_token {
        cmd.env_remove("COFFERAK_TOKEN");
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt;
        for (k, v) in &vars {
            cmd.env(k, std::ffi::OsStr::from_bytes(v));
        }
        let err = cmd.exec();
        eprintln!(
            "cofferak: run: could not start {:?}: {err}",
            args.command[0]
        );
        std::process::exit(127);
    }
}

/// Read a passphrase from `file` (first line), or prompt on the terminal
/// with echo off (twice when `confirm`).
fn read_passphrase(file: Option<&Path>, confirm: bool) -> zeroize::Zeroizing<String> {
    if let Some(path) = file {
        let s = zeroize::Zeroizing::new(
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| fail("passphrase", format!("{}: {e}", path.display()))),
        );
        return zeroize::Zeroizing::new(s.lines().next().unwrap_or("").to_string());
    }
    let first = prompt_hidden("Bundle passphrase: ");
    if confirm {
        let again = prompt_hidden("Repeat passphrase: ");
        if *first != *again {
            fail("passphrase", "the two entries don't match");
        }
    }
    first
}

#[cfg(unix)]
fn prompt_hidden(prompt: &str) -> zeroize::Zeroizing<String> {
    use std::io::{BufRead, Write};
    use std::os::unix::io::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .unwrap_or_else(|e| {
            fail(
                "passphrase",
                format!("no terminal to prompt on ({e}); use --passphrase-file"),
            )
        });
    let fd = tty.as_raw_fd();
    // SAFETY: plain termios calls on a file descriptor we own; the original
    // settings are restored before returning.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let have_term = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let original = term;
    if have_term {
        term.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut w = &tty;
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = zeroize::Zeroizing::new(String::new());
    let read = std::io::BufReader::new(&tty).read_line(&mut line);
    if have_term {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
    }
    let _ = writeln!(w);
    read.unwrap_or_else(|e| fail("passphrase", e));
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    line
}

/// Run `f` with each enrolled host of the vault whose sealed key file is on
/// this machine (preferring `$COFFERAK_HOST_ID`), returning the first
/// success; used by `export` and `import` to unlock the vault.
fn with_local_host<T>(
    data_dir: &Path,
    mut f: impl FnMut(&str, &dyn HostSeal) -> Result<T, commands::init::CliError>,
) -> Result<T, commands::init::CliError> {
    use commands::init::CliError;
    let vault =
        cofferak_core::format::VaultFile::load(&data_dir.join("vault.cofferak")).map_err(|e| {
            match e {
                cofferak_core::format::FormatError::Io(_) => CliError::VaultMissing,
                other => CliError::Format(other),
            }
        })?;
    let mut ids: Vec<String> = vault.hosts.keys().cloned().collect();
    if let Ok(pref) = std::env::var("COFFERAK_HOST_ID") {
        if let Some(i) = ids.iter().position(|h| *h == pref) {
            let h = ids.remove(i);
            ids.insert(0, h);
        }
    }
    let mut last = CliError::HostNotFound;
    for id in ids {
        if !data_dir.join("hosts").join(format!("{id}.seal")).exists() {
            continue;
        }
        let seal = current_host_seal(&id);
        match f(&id, seal.as_ref()) {
            Ok(v) => return Ok(v),
            Err(CliError::Invalid(m)) => return Err(CliError::Invalid(m)),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// When running as root via `sudo` (needed on Linux for admin commands),
/// hand a file we created back to the user who ran sudo, so they can
/// copy or delete it without sudo.
fn give_to_sudo_user(path: &Path) {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let parse = |v: &str| std::env::var(v).ok().and_then(|s| s.parse::<u32>().ok());
        if let (Some(uid), Some(gid)) = (parse("SUDO_UID"), parse("SUDO_GID")) {
            let _ = std::os::unix::fs::lchown(path, Some(uid), Some(gid));
        }
    }
}

fn selection(prefixes: &[String], with_tokens: bool) -> commands::transfer::Selection {
    commands::transfer::Selection {
        prefixes: prefixes.to_vec(),
        include_tokens: prefixes.is_empty() || with_tokens,
    }
}

fn cmd_export(args: ExportArgs) {
    let data_dir = resolve_data_dir(args.data_dir);
    if args.out.exists() && !args.force {
        fail(
            "export",
            format!("{} exists (use --force to overwrite)", args.out.display()),
        );
    }
    let sel = selection(&args.prefix, args.with_tokens);
    let (bytes, report) = if let Some(peer) = &args.to {
        with_admin_lock(&data_dir, || {
            with_local_host(&data_dir, |id, seal| {
                commands::transfer::run_export_to_peer_with_seal(&data_dir, id, seal, peer, &sel)
            })
        })
    } else {
        let pass = read_passphrase(args.passphrase_file.as_deref(), true);
        with_admin_lock(&data_dir, || {
            with_local_host(&data_dir, |id, seal| {
                commands::transfer::run_export_with_seal(
                    &data_dir,
                    id,
                    seal,
                    pass.as_bytes(),
                    cofferak_core::bundle::DEFAULT_ITERATIONS,
                    &sel,
                )
            })
        })
    }
    .unwrap_or_else(|e| fail("export", e));
    write_private(&args.out, &bytes, args.force).unwrap_or_else(|e| fail("export", e));
    give_to_sudo_user(&args.out);
    match &args.to {
        Some(peer) => println!(
            "exported {} secrets and {} service tokens to {} for peer '{peer}' (only that coffer can open it; signed by this one)",
            report.entries,
            report.services,
            args.out.display()
        ),
        None => {
            println!(
                "exported {} secrets and {} service tokens to {} (encrypted, mode 0600)",
                report.entries,
                report.services,
                args.out.display()
            );
            println!("keep the passphrase separately from the file; `cofferak import` needs both");
        }
    }
}

fn cmd_import(args: ImportArgs) {
    let data_dir = resolve_data_dir(args.data_dir);
    let meta = std::fs::metadata(&args.file)
        .unwrap_or_else(|e| fail("import", format!("{}: {e}", args.file.display())));
    if meta.len() > cofferak_core::bundle::MAX_BUNDLE_BYTES {
        fail("import", "bundle is too large");
    }
    let bytes = std::fs::read(&args.file)
        .unwrap_or_else(|e| fail("import", format!("{}: {e}", args.file.display())));
    let peer_transfer = commands::transfer::is_peer_transfer(&bytes);
    let pinned = args.from.as_ref().map(|f| read_identity_file(f));
    let pass = if peer_transfer {
        None
    } else {
        Some(read_passphrase(args.passphrase_file.as_deref(), false))
    };
    let r = with_admin_lock(&data_dir, || {
        with_local_host(&data_dir, |id, seal| {
            let key = match &pass {
                Some(p) => commands::transfer::ImportKey::Passphrase(p.as_bytes()),
                None => commands::transfer::ImportKey::Identity {
                    from: pinned.clone(),
                },
            };
            commands::transfer::run_import_with_seal(
                &data_dir,
                id,
                seal,
                &bytes,
                key,
                args.overwrite,
                args.dry_run,
            )
        })
    })
    .unwrap_or_else(|e| fail("import", e));
    let verb = if args.dry_run {
        "would import"
    } else {
        "imported"
    };
    let source = match &r.from_peer {
        Some(p) => format!("peer '{p}' (signature verified)"),
        None => format!(
            "vault {}…",
            &r.source_fingerprint[..r.source_fingerprint.len().min(16)]
        ),
    };
    println!(
        "{verb} from {source}: secrets {} new, {} replaced, {} kept; service tokens {} new, {} replaced, {} kept",
        r.entries_added,
        r.entries_replaced,
        r.entries_skipped.len(),
        r.services_added,
        r.services_replaced,
        r.services_skipped.len()
    );
    for p in r.entries_skipped.iter().take(20) {
        println!("  = {p} (exists, kept; use --overwrite to replace)");
    }
    for s in &r.services_skipped {
        println!("  = service {s} (exists, kept)");
    }
    if !args.dry_run {
        println!("re-encrypted under this coffer's own key; a running daemon picks the changes up automatically");
    }
}

fn read_identity_file(path: &Path) -> cofferak_core::identity::IdentityPublic {
    let text = if path.as_os_str() == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .unwrap_or_else(|e| fail("identity", e));
        s
    } else {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| fail("identity", format!("{}: {e}", path.display())))
    };
    cofferak_core::identity::IdentityPublic::from_text(&text)
        .unwrap_or_else(|e| fail("identity", format!("{}: {e}", path.display())))
}

fn cmd_identity(args: IdentityArgs) {
    let data_dir = resolve_data_dir(args.data_dir);
    let id = with_admin_lock(&data_dir, || {
        with_local_host(&data_dir, |h, seal| {
            commands::transfer::run_identity_with_seal(&data_dir, h, seal)
        })
    })
    .unwrap_or_else(|e| fail("identity", e));
    let text = format!(
        "# cofferak identity — fingerprint {}\n{}\n",
        id.short_fingerprint(),
        id.to_text()
    );
    if let Some(out) = &args.out {
        std::fs::write(out, &text)
            .unwrap_or_else(|e| fail("identity", format!("{}: {e}", out.display())));
        give_to_sudo_user(out);
        println!("wrote this coffer's public identity to {}", out.display());
        println!("fingerprint: {}", id.short_fingerprint());
        println!(
            "give the file to the other coffer and run there: cofferak peer add <name> {}",
            out.display()
        );
    } else {
        print!("{text}");
    }
}

fn cmd_peer(args: PeerArgs) {
    let data_dir = resolve_data_dir(args.data_dir);
    match args.command {
        PeerCommand::Add {
            name,
            identity_file,
            replace,
        } => {
            let peer = read_identity_file(&identity_file);
            with_admin_lock(&data_dir, || {
                with_local_host(&data_dir, |h, seal| {
                    commands::transfer::run_peer_add_with_seal(
                        &data_dir, h, seal, &name, &peer, replace,
                    )
                })
            })
            .unwrap_or_else(|e| fail("peer add", e));
            println!(
                "trusting peer '{name}' (fingerprint {})",
                peer.short_fingerprint()
            );
            println!("confirm this fingerprint with the other side over a channel you trust");
        }
        PeerCommand::List => {
            let peers = with_admin_lock(&data_dir, || {
                with_local_host(&data_dir, |h, seal| {
                    commands::transfer::run_peer_list_with_seal(&data_dir, h, seal)
                })
            })
            .unwrap_or_else(|e| fail("peer list", e));
            if peers.is_empty() {
                println!("no trusted peers yet (add one with `cofferak peer add <name> <identity file>`)");
            }
            for (name, p) in peers {
                println!("{name:20} {}", p.short_fingerprint());
            }
        }
        PeerCommand::Rm { name } => {
            let removed = with_admin_lock(&data_dir, || {
                commands::transfer::run_peer_rm(&data_dir, &name)
            })
            .unwrap_or_else(|e| fail("peer rm", e));
            if removed {
                println!("no longer trusting peer '{name}'");
            } else {
                fail("peer rm", format!("no peer named {name}"));
            }
        }
    }
}
