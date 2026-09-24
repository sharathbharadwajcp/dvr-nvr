# Open Digital Video Forensics Platform (DVR/NVR)

A unified, vendor-agnostic digital forensic analysis and recovery platform for surveillance digital/network video recorders (DVR/NVRs).

Engineered to standardize the acquisition, recovery, analysis, validation, and reporting of surveillance evidence across proprietary storage formats, filesystems, and video encoding mechanisms.

---

## 🌟 Key Features

* **Strict Read-Only Acquisition**: Streams and hashes physical drives or image files block-by-block with zero write syscalls. Generates MD5, SHA-256, and BLAKE3 cryptographic hashes with verified manifest outputs.
* **Declarative Format Grammars**: Parses proprietary filesystems using declarative YAML specifications (AST interpretation) instead of fragile vendor-specific reverse-engineered binary blobs.
* **Pre-Acquisition Device Identification**: Dynamically interrogates Sector 0 and video bitstream headers to detect OEM vendor, model family, SoC chipset, and calibrated confidence without guessing.
* **Multi-OEM Support**:
  * **Hikvision** (DS-7000/8000 Series, HBFS Master Sector at offset 512, Hikvision MP4 exports)
  * **Dahua** (DHFS filesystem, DHAV/DAV proprietary frame containers)
  * **CP Plus** (CPPLUS/CP-PLUS brand markers & DHFS hybrid layouts)
  * **Uniview** (UNIVIEW / UNV proprietary block allocation)
  * **Matrix Comsec** (SATATYA series direct sector storage)
  * **Godrej** (SeeThru series non-standard containers)
  * **TP-Link** (VIGI surveillance series ring buffer)
  * **Honeywell Security** (RIFF AVI / MP4 surveillance streams)
* **Deep Bitstream Recovery & Carving**: Recovers orphan, deleted, or corrupted video frames when metadata tables or sector headers are zeroed, using pure-Rust H.264 / H.265 Annex B NAL unit parsers.
* **Visual Video Analytics & Motion Triage**: Computes frame-by-frame visual motion energy gradients, identifies motion bounding boxes, and prioritizes investigative leads without external heavy model dependencies.
* **Multi-Camera Timeline Correlation**: Monotonically correlates timestamps across multiple channels, automatically identifying cross-camera transit events and synchronous blackout anomalies.
* **Sandboxed WASM Runtime**: Isolated Wasmtime sandbox enforcing 16 MiB memory limits and 500 ms execution watchdogs for untrusted descramblers and vendor plugins.
* **Section 63 BSA Legal Certificates**: Automatically produces court-admissible forensic certificates complying with Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023, complete with cryptographic hash verification and examiner declarations.
* **Dual Interface**:
  * **CLI Tool (`dvrft`)**: 9 subcommands for automated forensic batch scripts and lab pipelines.
  * **Desktop Workstation GUI**: Dark-themed forensic workstation embedded in pure Rust (`http://127.0.0.1:8080`).

---

## 🏛 Architecture Overview

The platform is structured as a modular 10-crate Rust workspace:

```
dvr-forensics/
├── Cargo.toml                  # Root workspace configuration
├── docs/                       # Comprehensive forensic documentation suite
│   ├── comparative-oem-analysis.md
│   ├── system-architecture.md
│   ├── sop.md
│   ├── validation-report.md
│   ├── user-manual.md
│   └── final-project-report.md
├── grammars/                   # Declarative YAML format grammars
│   ├── synthetic-v1.yaml       # Tier 1 ground-truth reference grammar
│   ├── hikvision-v1.yaml       # Tier 2 literature-derived HBFS grammar
│   ├── dahua-v1.yaml           # Tier 2 literature-derived DHFS/DHAV grammar
│   └── vendor_registry.yaml    # Tier 0 anti-hallucination vendor registry
├── plugins/                    # WebAssembly descrambler plugins
│   └── c4_xor_descrambler.wasm
├── samples/                    # Test fixtures, ground truth disks, and sample streams
└── engine/                     # Rust crates
    ├── crates/acquisition      # Read-only bit-stream acquisition & multi-hashing
    ├── crates/dvrft-gen        # Synthetic ground-truth disk image generator
    ├── crates/parser           # Declarative YAML grammar DSL & SQLite WAL schema
    ├── crates/identify         # Byte-level OEM & container signature interrogator
    ├── crates/sandbox          # Wasmtime runtime with strict resource ceilings
    ├── crates/recovery         # Deep H.264/H.265 NAL carver & LBA tamper auditor
    ├── crates/correlation      # Multi-channel timeline fusion & anomaly detection
    ├── crates/analytics        # Motion energy gradient estimation & lead triage
    ├── crates/reporting        # Section 63 BSA PDF certificate & audit generator
    ├── crates/gui              # Embedded forensic workstation desktop interface
    └── crates/dvrft            # Unified CLI binary entrypoint
```

---

## 🚀 Getting Started

### Prerequisites

* [Rust 1.78+](https://www.rust-lang.org/tools/install) (2021 edition)
* Windows, Linux, or macOS

### Build

To compile all workspace crates in debug mode:

```bash
cargo build --workspace
```

To compile optimized release binaries:

```bash
cargo build --release
```

Release binaries will be generated in `engine/target/release/`:
* `dvrft` (Command-Line Interface)
* `gui` (Desktop Forensic Workstation)

---

## 🧪 Running Automated Tests

The platform includes a comprehensive test suite covering all 10 crates:

```bash
cargo test --workspace
```

*All 44 automated tests pass with 100% green status.*

---

## 🖥 Using the Desktop GUI Workstation

Launch the workstation GUI server:

```bash
cargo run -p gui
```

Open your browser to:
```
http://127.0.0.1:8080
```

The GUI consists of 5 dedicated screens:
1. **Screen 1 · Evidence Acquisition**: Point to any physical device, raw image, or stream dump. Compute SHA-256, MD5, and BLAKE3 hashes with strict read-only guarantees.
2. **Screen 2 · Device Identification**: Interrogate any disk dump or video file (`.mp4`, `.dav`, `.avi`, `.mkv`, `.h264`). Displays detected OEM, chipset family, validation tier, and calibrated confidence score.
3. **Screen 3 · Parse & Recovery**: Inspect parsed multi-channel video streams (Ch. A, Ch. B), recovered/carved orphan frames, and raw hex inspector.
4. **Screen 4 · Timeline & CCTV Analytics**: Analyze CCTV video files directly for motion clusters and entity proposals, or visualize multi-camera cross-transitions and blackout alerts.
5. **Screen 5 · Section 63 Certificate**: Generate and export court-admissible Section 63 BSA certificates and audit reports.

---

## 💻 Using the Command-Line Interface (`dvrft`)

The unified CLI provides 9 subcommands:

```bash
# 1. Read-only acquisition
dvrft acquire /dev/sdb --case CASE-2026-001 --out-dir ./cases/case-001

# 2. Pre-acquisition device identification
dvrft identify ./evidence.img --grammars-dir ./grammars

# 3. Structured parsing via declarative grammar
dvrft parse ./cases/case-001 --grammars-dir ./grammars

# 4. Integrity verification and audit
dvrft verify ./cases/case-001

# 5. Deep H.264 bitstream carving
dvrft carve ./cases/case-001 --out-dir ./carved_clips

# 6. Query evidence database
dvrft query ./cases/case-001/case.db --channel 1 --keyframes

# 7. Multi-camera timeline correlation
dvrft correlate ./cases/case-001/case.db --window-secs 10

# 8. Motion energy analytics & visual triage
dvrft analyze ./cases/case-001/case.db

# 9. Generate forensic report & Section 63 BSA certificate
dvrft report ./cases/case-001 --examiner-name "Forensic Officer" --agency-name "Digital Forensic Lab"
```

---

## 📄 Documentation

Comprehensive technical documentation is available in [`docs/`](docs/):
* [`comparative-oem-analysis.md`](docs/comparative-oem-analysis.md): In-depth analysis of 8 surveillance OEMs, filesystem layouts, and SoCs.
* [`system-architecture.md`](docs/system-architecture.md): Technical architecture, data flow diagrams, database schema, and sandbox specifications.
* [`sop.md`](docs/sop.md): Standard Operating Procedures for law enforcement and digital forensics laboratories.
* [`validation-report.md`](docs/validation-report.md): Empirical validation audit across Tier 1, Tier 2, and Tier 0 formats.
* [`user-manual.md`](docs/user-manual.md): Comprehensive operator manual for CLI commands and GUI workstation.
* [`final-project-report.md`](docs/final-project-report.md): Executive summary, forensic findings, and development roadmap.

---

## ⚖️ Legal & Forensic Compliance

* Compliant with **Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023** (electronic evidence admissibility).
* Conforms to **ISO/IEC 27037** standards for digital evidence handling (identification, collection, acquisition, and preservation).
* Dual-hash verification (SHA-256 + MD5) ensuring cryptographic chain-of-custody integrity.
