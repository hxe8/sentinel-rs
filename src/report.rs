use std::fmt::Write as _;
use std::fs;

use crate::config::Config;
use crate::error::AppResult;
use crate::model::{FileFinding, ScanReport};

pub fn write_output(report: &ScanReport, config: &Config) -> AppResult<()> {
    if let Some(path) = &config.output_json {
        fs::write(path, to_json(report))?;
        if !config.quiet {
            println!("report written to {}", path.display());
        }
    }
    Ok(())
}

pub fn print_summary(report: &ScanReport) {
    println!("\n== sentinel-rs summary ==");
    println!("root: {}", report.root);
    println!("generated_at_epoch: {}", report.generated_at_epoch);
    println!("scanned_files: {}", report.stats.scanned_files);
    println!("skipped_files: {}", report.stats.skipped_files);
    println!("suspicious_files: {}", report.stats.suspicious_files);
    println!("total_bytes: {}", report.stats.total_bytes);

    if report.findings.is_empty() {
        println!("\nno suspicious findings matched the current rules.");
        return;
    }

    println!("\ntop findings:");
    for finding in report.findings.iter().take(10) {
        println!(
            "- [{}] score={} entropy={:.2} path={}",
            finding.category, finding.suspicion_score, finding.entropy, finding.path
        );
        for reason in &finding.reasons {
            println!("    • {}", reason);
        }
    }
}

pub fn to_json(report: &ScanReport) -> String {
    let mut output = String::with_capacity(4096);
    output.push('{');

    push_key(&mut output, "generated_at_epoch");
    let _ = write!(output, "{}", report.generated_at_epoch);
    output.push(',');

    push_key(&mut output, "root");
    push_json_string(&mut output, &report.root);
    output.push(',');

    push_key(&mut output, "stats");
    output.push('{');
    push_key(&mut output, "scanned_files");
    let _ = write!(output, "{}", report.stats.scanned_files);
    output.push(',');
    push_key(&mut output, "skipped_files");
    let _ = write!(output, "{}", report.stats.skipped_files);
    output.push(',');
    push_key(&mut output, "suspicious_files");
    let _ = write!(output, "{}", report.stats.suspicious_files);
    output.push(',');
    push_key(&mut output, "total_bytes");
    let _ = write!(output, "{}", report.stats.total_bytes);
    output.push('}');
    output.push(',');

    push_key(&mut output, "findings");
    output.push('[');
    for (index, finding) in report.findings.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_finding(&mut output, finding);
    }
    output.push(']');

    output.push('}');
    output
}

fn push_finding(output: &mut String, finding: &FileFinding) {
    output.push('{');

    push_key(output, "path");
    push_json_string(output, &finding.path);
    output.push(',');

    push_key(output, "size");
    let _ = write!(output, "{}", finding.size);
    output.push(',');

    push_key(output, "sha256");
    push_json_string(output, &finding.sha256);
    output.push(',');

    push_key(output, "entropy");
    let _ = write!(output, "{:.2}", finding.entropy);
    output.push(',');

    push_key(output, "extension");
    push_json_string(output, &finding.extension);
    output.push(',');

    push_key(output, "suspicion_score");
    let _ = write!(output, "{}", finding.suspicion_score);
    output.push(',');

    push_key(output, "category");
    push_json_string(output, &finding.category);
    output.push(',');

    push_key(output, "reasons");
    output.push('[');
    for (index, reason) in finding.reasons.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        push_json_string(output, reason);
    }
    output.push(']');

    output.push('}');
}

fn push_key(output: &mut String, key: &str) {
    push_json_string(output, key);
    output.push(':');
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control.is_control() => {
                let _ = write!(output, "\\u{:04x}", control as u32);
            }
            other => output.push(other),
        }
    }
    output.push('"');
}
