mod commands;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use commands::enroll::{run_enroll_host_with_seal, run_enroll_service};
use commands::init::{current_host_seal, run_init_host, run_init_root};
use cofferak_core::acl::Permission;

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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => {
            let data_dir = resolve_data_dir(args.data_dir);

            match (args.root, args.host) {
                (true, None) => match run_init_root(&data_dir) {
                    Ok(fingerprint) => {
                        println!("vault initialized; root public key fingerprint: {fingerprint}");
                    }
                    Err(e) => {
                        eprintln!("cofferak-cli: init --root failed: {e}");
                        std::process::exit(1);
                    }
                },
                (false, Some(host_id)) => match run_init_host(&data_dir, &host_id) {
                    Ok(()) => {
                        println!("host '{host_id}' enrolled");
                    }
                    Err(e) => {
                        eprintln!("cofferak-cli: init --host failed: {e}");
                        std::process::exit(1);
                    }
                },
                (true, Some(_)) => {
                    // Unreachable in practice: clap's `conflicts_with`
                    // rejects `--root` together with `--host` before we get
                    // here, but handled explicitly rather than panicking.
                    eprintln!("cofferak-cli: pass exactly one of --root or --host");
                    std::process::exit(2);
                }
                (false, None) => {
                    eprintln!("cofferak-cli: pass one of --root or --host <id>");
                    std::process::exit(2);
                }
            }
        }
        Command::EnrollHost(args) => {
            let data_dir = resolve_data_dir(args.data_dir);

            let this_host_seal = current_host_seal(&args.this_host_id);
            let new_host_seal = current_host_seal(&args.new_host_id);

            match run_enroll_host_with_seal(
                &data_dir,
                &args.this_host_id,
                &args.new_host_id,
                this_host_seal.as_ref(),
                new_host_seal.as_ref(),
            ) {
                Ok(()) => {
                    println!("host '{}' enrolled", args.new_host_id);
                }
                Err(e) => {
                    eprintln!("cofferak-cli: enroll-host failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::EnrollService(args) => {
            let data_dir = resolve_data_dir(args.data_dir);

            let prefixes: Vec<String> = args
                .paths
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();

            match run_enroll_service(
                &data_dir,
                &args.service_id,
                prefixes,
                args.perm.into_permission(),
            ) {
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
                    eprintln!("cofferak-cli: enroll-service failed: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
