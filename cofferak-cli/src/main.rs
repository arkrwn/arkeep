mod commands;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use commands::init::{run_init_host, run_init_root};

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
    }
}
