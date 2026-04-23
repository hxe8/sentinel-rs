use std::fs;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::AppResult;

#[derive(Debug, Default)]
pub struct WalkResult {
    pub files: Vec<FileEntry>,
    pub skipped: u64,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
}

pub fn collect_files(config: &Config) -> AppResult<WalkResult> {
    let mut result = WalkResult::default();

    match fs::symlink_metadata(&config.root) {
        Ok(metadata) if metadata.is_file() => {
            result.files.push(FileEntry {
                path: config.root.clone(),
                size: metadata.len(),
            });
        }
        Ok(_) => {
            visit_dir(&config.root, 0, config, &mut result)?;
        }
        Err(_) => result.skipped += 1,
    }

    Ok(result)
}

fn visit_dir(path: &Path, depth: usize, config: &Config, result: &mut WalkResult) -> AppResult<()> {
    if let Some(max_depth) = config.max_depth {
        if depth > max_depth {
            return Ok(());
        }
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => {
            result.skipped += 1;
            return Ok(());
        }
    };

    for entry_result in entries {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => {
                result.skipped += 1;
                continue;
            }
        };

        let entry_path = entry.path();

        if !config.include_hidden && is_hidden(&entry_path) {
            continue;
        }

        let metadata = match fs::symlink_metadata(&entry_path) {
            Ok(metadata) => metadata,
            Err(_) => {
                result.skipped += 1;
                continue;
            }
        };

        let file_type = metadata.file_type();

        if file_type.is_symlink() && !config.follow_symlinks {
            result.skipped += 1;
            continue;
        }

        if metadata.is_dir() {
            visit_dir(&entry_path, depth + 1, config, result)?;
        } else if metadata.is_file() {
            result.files.push(FileEntry {
                path: entry_path,
                size: metadata.len(),
            });
        } else if file_type.is_symlink() && config.follow_symlinks {
            match fs::metadata(&entry_path) {
                Ok(target_meta) if target_meta.is_dir() => {
                    visit_dir(&entry_path, depth + 1, config, result)?;
                }
                Ok(target_meta) if target_meta.is_file() => {
                    result.files.push(FileEntry {
                        path: entry_path,
                        size: target_meta.len(),
                    });
                }
                _ => result.skipped += 1,
            }
        }
    }

    Ok(())
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with('.'))
        .unwrap_or(false)
}
