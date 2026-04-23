mod cli;
mod config;
mod error;
mod fswalk;
mod hash;
mod model;
mod report;
mod scanner;

use cli::{Cli, Command};
use error::AppResult;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let cli = Cli::parse(std::env::args())?;

    match cli.command {
        Command::Help => {
            Cli::print_help();
            Ok(())
        }
        Command::Scan(scan_args) => {
            let config = scan_args.into_config();
            let report = scanner::scan(&config)?;
            report::write_output(&report, &config)?;
            if !config.quiet {
                report::print_summary(&report);
            }
            Ok(())
        }
    }
}
