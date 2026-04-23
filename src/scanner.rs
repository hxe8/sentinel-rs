use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::error::AppResult;
use crate::fswalk::collect_files;
use crate::hash::sha256_hex;
use crate::model::{FileFinding, ReportStats, ScanReport};

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "jse", "jar", "scr", "hta", "msi",
    "apk", "dmg", "pkg", "iso", "lnk", "docm", "xlsm", "pptm", "reg",
];

pub fn scan(config: &Config) -> AppResult<ScanReport> {
    let walked = collect_files(config)?;
    let mut stats = ReportStats {
        skipped_files: walked.skipped,
        ..ReportStats::default()
    };
    let mut findings = Vec::new();

    for entry in walked.files {
        if entry.size > config.max_size_bytes {
            stats.skipped_files += 1;
            continue;
        }

        let bytes = match fs::read(&entry.path) {
            Ok(bytes) => bytes,
            Err(_) => {
                stats.skipped_files += 1;
                continue;
            }
        };

        stats.scanned_files += 1;
        stats.total_bytes = stats.total_bytes.saturating_add(entry.size);

        let entropy = calculate_entropy(&bytes);
        let sha256 = sha256_hex(&bytes);
        let extension = extension_of(&entry.path);
        let reasons = collect_reasons(&entry.path, &extension, entropy, bytes.len(), config);
        let score = score_from_reasons(&reasons, entropy, &extension, bytes.len());

        if score > 0 {
            stats.suspicious_files += 1;
            findings.push(FileFinding {
                path: entry.path.to_string_lossy().replace('\\', "/"),
                size: entry.size,
                sha256,
                entropy: round2(entropy),
                extension,
                suspicion_score: score,
                category: classify(score).to_string(),
                reasons,
            });
        }
    }

    findings.sort_by(|left, right| {
        right
            .suspicion_score
            .cmp(&left.suspicion_score)
            .then_with(|| left.path.cmp(&right.path))
    });

    Ok(ScanReport {
        generated_at_epoch: now_epoch(),
        root: config.root.to_string_lossy().replace('\\', "/"),
        stats,
        findings,
    })
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn extension_of(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn collect_reasons(
    path: &Path,
    extension: &str,
    entropy: f64,
    byte_len: usize,
    config: &Config,
) -> Vec<String> {
    let mut reasons = Vec::new();
    let file_name = path.file_name().and_then(|value| value.to_str()).unwrap_or("");
    let file_name_lower = file_name.to_ascii_lowercase();
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();

    if SUSPICIOUS_EXTENSIONS.contains(&extension) {
        reasons.push(format!("suspicious executable/script extension: .{extension}"));
    }

    if file_name_lower.matches('.').count() >= 2 {
        if ["pdf", "png", "jpg", "jpeg", "doc", "docx", "txt", "xls", "xlsx"]
            .iter()
            .any(|fake| file_name_lower.contains(&format!(".{fake}.")))
        {
            reasons.push("double extension masquerading pattern".to_string());
        }
    }

    if file_name.starts_with('.') {
        reasons.push("hidden file name".to_string());
    }

    if entropy >= config.min_entropy {
        reasons.push(format!(
            "high entropy content ({:.2} >= {:.2})",
            entropy, config.min_entropy
        ));
    }

    if byte_len > 0 && byte_len < 2048 && ["js", "vbs", "bat", "cmd", "ps1"].contains(&extension) {
        reasons.push("very small script file".to_string());
    }

    if normalized.contains("/temp/")
        || normalized.contains("/tmp/")
        || normalized.contains("/appdata/local/temp/")
        || normalized.contains("/downloads/")
    {
        reasons.push("user-writable execution-prone location".to_string());
    }

    reasons
}

fn score_from_reasons(reasons: &[String], entropy: f64, extension: &str, byte_len: usize) -> u8 {
    if reasons.is_empty() {
        return 0;
    }

    let mut score: u8 = 0;

    for reason in reasons {
        let add = if reason.contains("suspicious executable/script extension") {
            35
        } else if reason.contains("double extension") {
            25
        } else if reason.contains("high entropy") {
            20
        } else if reason.contains("execution-prone location") {
            10
        } else if reason.contains("hidden") {
            10
        } else if reason.contains("small script") {
            15
        } else {
            5
        };
        score = score.saturating_add(add);
    }

    if entropy > 7.8 {
        score = score.saturating_add(10);
    }

    if ["exe", "dll", "scr", "jar", "msi"].contains(&extension) && byte_len > 0 {
        score = score.saturating_add(5);
    }

    score.min(100)
}

fn classify(score: u8) -> &'static str {
    match score {
        0 => "none",
        1..=34 => "low",
        35..=64 => "medium",
        _ => "high",
    }
}

fn calculate_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0;

    for count in counts {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }

    entropy
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::calculate_entropy;

    #[test]
    fn low_entropy_text_is_low() {
        let entropy = calculate_entropy(b"aaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(entropy < 1.0);
    }

    #[test]
    fn mixed_bytes_have_higher_entropy() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let entropy = calculate_entropy(&bytes);
        assert!(entropy > 7.5);
    }
}
