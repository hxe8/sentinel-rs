use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub root: PathBuf,
    pub output_json: Option<PathBuf>,
    pub max_size_bytes: u64,
    pub min_entropy: f64,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub max_depth: Option<usize>,
    pub quiet: bool,
}
