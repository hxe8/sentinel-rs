# sentinel-rs

`sentinel-rs` is a defensive file triage scanner written in Rust.

It recursively scans a directory, computes a SHA-256 digest for each eligible file, estimates byte entropy, applies a small set of suspicious-file heuristics, and optionally exports a JSON report.

This repository is built to look like a serious systems/security project:
- no external dependencies
- modular source layout
- custom SHA-256 implementation
- unit tests for hashing and entropy helpers
- CLI usage with configurable thresholds

## Features

- Recursive directory traversal
- Custom SHA-256 implementation in pure Rust
- Byte entropy analysis
- Suspicious extension and masquerading checks
- Simple risk scoring (`low`, `medium`, `high`)
- JSON report output
- Hidden file and symlink controls
- Max file size and max depth limits

## Example usage

```bash
cargo run -- scan ./samples --json report.json
cargo run -- scan ./samples --max-size-mb 8 --min-entropy 7.6
cargo run -- scan ./samples --hidden --max-depth 3
cargo run -- scan ./samples --quiet --json report.json
```

## Example output

```text
== sentinel-rs summary ==
root: ./samples
generated_at_epoch: 1770000000
scanned_files: 42
skipped_files: 3
suspicious_files: 6
total_bytes: 1289203

top findings:
- [high] score=70 entropy=7.91 path=./samples/update.pdf.exe
    • suspicious executable/script extension: .exe
    • double extension masquerading pattern
    • high entropy content (7.91 >= 7.20)
```

## JSON report shape

```json
{
  "generated_at_epoch": 1770000000,
  "root": "./samples",
  "stats": {
    "scanned_files": 42,
    "skipped_files": 3,
    "suspicious_files": 6,
    "total_bytes": 1289203
  },
  "findings": [
    {
      "path": "./samples/update.pdf.exe",
      "size": 182272,
      "sha256": "...",
      "entropy": 7.91,
      "extension": "exe",
      "suspicion_score": 70,
      "category": "high",
      "reasons": [
        "suspicious executable/script extension: .exe",
        "double extension masquerading pattern",
        "high entropy content (7.91 >= 7.20)"
      ]
    }
  ]
}
```

## Project layout

```text
sentinel-rs/
├── Cargo.toml
├── README.md
├── LICENSE
└── src/
    ├── cli.rs
    ├── config.rs
    ├── error.rs
    ├── fswalk.rs
    ├── hash.rs
    ├── main.rs
    ├── model.rs
    ├── report.rs
    └── scanner.rs
```

## How it scores files

The scoring model is intentionally simple and explainable. The scanner adds points for:
- executable or script-like extensions
- double-extension masquerading patterns like `invoice.pdf.exe`
- very high entropy content
- hidden filenames
- small script droppers
- temp/download-style locations

This is not an antivirus engine. It is a triage and inspection tool.

## Build

```bash
cargo build
cargo test
cargo run -- --help
```

## Notes

- The repository uses only the Rust standard library.
- Large files are skipped by default to keep scans predictable.
- The custom hash implementation is included for educational and portfolio value.

## Good next upgrades

- multithreaded scanning
- file signature / magic-byte checks
- allowlist / ignore patterns
- baseline snapshots and diff mode
- CSV output
- TUI dashboard

## License

MIT
