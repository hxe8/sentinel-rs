use std::path::PathBuf;

use crate::config::Config;
use crate::error::{AppError, AppResult};

pub struct Cli {
    pub command: Command,
}

pub enum Command {
    Scan(ScanArgs),
    Help,
}

#[derive(Debug, Clone)]
pub struct ScanArgs {
    pub path: PathBuf,
    pub output_json: Option<PathBuf>,
    pub max_size_mb: u64,
    pub min_entropy: f64,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub max_depth: Option<usize>,
    pub quiet: bool,
}

impl Cli {
    pub fn parse<I>(args: I) -> AppResult<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut values: Vec<String> = args.into_iter().collect();
        if !values.is_empty() {
            values.remove(0);
        }

        if values.is_empty() {
            return Ok(Self {
                command: Command::Help,
            });
        }

        match values[0].as_str() {
            "help" | "--help" | "-h" => Ok(Self {
                command: Command::Help,
            }),
            "scan" => Ok(Self {
                command: Command::Scan(Self::parse_scan(values.into_iter().skip(1).collect())?),
            }),
            other => Err(AppError::InvalidArgs(format!(
                "unknown command '{other}'. use 'scan' or '--help'"
            ))),
        }
    }

    fn parse_scan(args: Vec<String>) -> AppResult<ScanArgs> {
        if args.is_empty() {
            return Err(AppError::InvalidArgs(
                "missing path. usage: sentinel-rs scan <path> [options]".to_string(),
            ));
        }

        let path = PathBuf::from(&args[0]);
        let mut output_json = None;
        let mut max_size_mb = 32;
        let mut min_entropy = 7.2;
        let mut include_hidden = false;
        let mut follow_symlinks = false;
        let mut max_depth = None;
        let mut quiet = false;

        let mut index = 1;
        while index < args.len() {
            match args[index].as_str() {
                "--json" => {
                    index += 1;
                    let value = args.get(index).ok_or_else(|| {
                        AppError::InvalidArgs("--json requires a file path".to_string())
                    })?;
                    output_json = Some(PathBuf::from(value));
                }
                "--max-size-mb" => {
                    index += 1;
                    let value = args.get(index).ok_or_else(|| {
                        AppError::InvalidArgs("--max-size-mb requires a number".to_string())
                    })?;
                    max_size_mb = value.parse::<u64>().map_err(|_| {
                        AppError::InvalidArgs("--max-size-mb must be an integer".to_string())
                    })?;
                }
                "--min-entropy" => {
                    index += 1;
                    let value = args.get(index).ok_or_else(|| {
                        AppError::InvalidArgs("--min-entropy requires a number".to_string())
                    })?;
                    min_entropy = value.parse::<f64>().map_err(|_| {
                        AppError::InvalidArgs("--min-entropy must be a decimal number".to_string())
                    })?;
                }
                "--max-depth" => {
                    index += 1;
                    let value = args.get(index).ok_or_else(|| {
                        AppError::InvalidArgs("--max-depth requires a number".to_string())
                    })?;
                    max_depth = Some(value.parse::<usize>().map_err(|_| {
                        AppError::InvalidArgs("--max-depth must be an integer".to_string())
                    })?);
                }
                "--hidden" => include_hidden = true,
                "--follow-symlinks" => follow_symlinks = true,
                "--quiet" => quiet = true,
                other => {
                    return Err(AppError::InvalidArgs(format!(
                        "unknown option '{other}'. use '--help' for usage"
                    )))
                }
            }
            index += 1;
        }

        Ok(ScanArgs {
            path,
            output_json,
            max_size_mb,
            min_entropy,
            include_hidden,
            follow_symlinks,
            max_depth,
            quiet,
        })
    }

    pub fn print_help() {
        println!(
            "sentinel-rs\n\n\
             Defensive file triage scanner written in Rust.\n\n\
             Usage:\n\
               sentinel-rs scan <path> [options]\n\n\
             Options:\n\
               --json <file>           Write a JSON report\n\
               --max-size-mb <n>       Skip files larger than n MB (default: 32)\n\
               --min-entropy <f>       Mark files above entropy threshold (default: 7.2)\n\
               --max-depth <n>         Limit recursion depth\n\
               --hidden                Include hidden files and folders\n\
               --follow-symlinks       Follow symlinks\n\
               --quiet                 Reduce stdout output\n\
               -h, --help              Show this help\n"
        );
    }
}

impl ScanArgs {
    pub fn into_config(self) -> Config {
        Config {
            root: self.path,
            output_json: self.output_json,
            max_size_bytes: self.max_size_mb * 1024 * 1024,
            min_entropy: self.min_entropy,
            include_hidden: self.include_hidden,
            follow_symlinks: self.follow_symlinks,
            max_depth: self.max_depth,
            quiet: self.quiet,
        }
    }
}
