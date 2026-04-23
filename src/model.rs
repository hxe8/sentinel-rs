#[derive(Debug, Clone)]
pub struct ScanReport {
    pub generated_at_epoch: u64,
    pub root: String,
    pub stats: ReportStats,
    pub findings: Vec<FileFinding>,
}

#[derive(Debug, Clone, Default)]
pub struct ReportStats {
    pub scanned_files: u64,
    pub skipped_files: u64,
    pub suspicious_files: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct FileFinding {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub entropy: f64,
    pub extension: String,
    pub suspicion_score: u8,
    pub category: String,
    pub reasons: Vec<String>,
}
