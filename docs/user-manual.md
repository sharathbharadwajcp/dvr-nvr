# User Manual: Open Digital Video Forensics Platform

**Project**: Open Digital Video Forensics Platform for CCTV/DVR/NVR Systems  
**Initiative**: Smart India Hackathon (SIH 2025) | Team Cyber 4  
**Target Audience**: Digital Forensic Examiners, LEA Investigators, Incident Responders  
**Version**: 1.0.0  

---

## 1. Introduction & Overview

The **Open Digital Video Forensics Platform** is an enterprise-grade, air-gapped forensic suite designed specifically for recovering, authenticating, and analyzing surveillance video footage stored on proprietary CCTV, DVR, and NVR storage devices.

The platform provides two operational interfaces:
1. **`dvrft` CLI**: A fast, scriptable command-line interface for headless lab automation, batch processing, and server-grade forensic pipelines.
2. **Desktop GUI Workstation**: An embedded, zero-dependency browser-based forensic workstation (`127.0.0.1:8080`) providing interactive visualization of timeline correlations, AI motion analysis, and Section 63 BSA PDF generation.

---

## 2. Installation & Quick Start

### 2.1. System Requirements
- **Operating System**: Windows 10/11 (64-bit), Ubuntu Linux 20.04+, or macOS 12+
- **Processor**: x86_64 or ARM64 (AVX2 support recommended for accelerated hashing)
- **Memory**: Minimum 4 GB RAM (8 GB+ recommended for large multi-terabyte drives)
- **Storage**: Fast NVMe/SSD workspace for raw image storage and SQLite WAL cache
- **External Dependencies**: Zero. All cryptographic algorithms, SQLite drivers, WASM runtimes, and PDF generators are compiled directly into the binary.

### 2.2. Building from Source
Clone the repository and compile using the standard Rust toolchain:
```bash
cd engine
cargo build --release
```
The compiled binaries will be located in `engine/target/release/`:
- `dvrft.exe`: Primary forensic CLI
- `gui.exe`: Desktop GUI application
- `dvrft-gen.exe`: Synthetic disk test fixture generator

---

## 3. Command-Line Interface (`dvrft`) Reference

### 3.1. Command Summary
```
dvrft [SUBCOMMAND] [OPTIONS]

SUBCOMMANDS:
    acquire      Perform bit-stream forensic acquisition with SHA-256/MD5/BLAKE3 hashing
    identify     Interrogate disk headers for OEM signatures, SoCs, and confidence scoring
    parse        Parse proprietary filesystems via declarative YAML grammars into SQLite
    verify       Verify block-level cryptographic integrity and detect sector tampering
    carve        Deep carve raw H.264 NAL units from unallocated or damaged sectors
    query        Query parsed channels, streams, and frames from the case database
    correlate    Perform multi-camera timeline fusion and synchronous blackout detection
    analyze      Run visual motion energy estimation and entity proposal triage
    report       Generate forensic reports, Section 63 BSA PDF certificates, and video clips
```

---

### 3.2. `dvrft acquire`
Performs bit-stream image acquisition with dual whole-image hashing and block-level BLAKE3 tree generation.
```bash
dvrft acquire --source \\.\PhysicalDrive2 --output C:\Evidence\disk.dd
```
**Flags & Arguments**:
- `--source <PATH>`: Physical device path (e.g., `\\.\PhysicalDrive2` on Windows, `/dev/sdb` on Linux) or raw image file.
- `--output <PATH>`: Destination path for the `.dd` raw image file.
- `--block-size <BYTES>`: Buffer chunk size (default: 524,288 bytes / 512 KiB).

**Output**:
- The bit-stream raw image file.
- `acquisition_manifest.json` containing whole-image SHA-256, whole-image MD5, and per-block BLAKE3 hashes.

---

### 3.3. `dvrft identify`
Interrogates Sector 0 and heuristic offsets to detect the OEM filesystem, SoC family, and validation tier.
```bash
dvrft identify --image C:\Evidence\disk.dd
```
**Example Output**:
```
Device Identification Summary:
  Detected Format : Hikvision HIKFS (HIKVISION_V1)
  Validation Tier : Tier 2 (Literature-Derived)
  Confidence Score: 95.0%
  Target SoC      : HiSilicon Hi3520D / Hi3531A
  Recommended Gram: grammars/hikvision-v1.yaml
```

---

### 3.4. `dvrft parse`
Interprets the physical drive or raw image using declarative YAML grammars and populates the SQLite case database.
```bash
dvrft parse --image C:\Evidence\disk.dd --grammar grammars/dahua-v1.yaml --case-id CASE-2025-01
```
**Flags & Arguments**:
- `--image <PATH>`: Path to the raw forensic image.
- `--grammar <PATH>`: Path to the YAML grammar file.
- `--case-id <STRING>`: Unique case identifier.
- `--db <PATH>`: SQLite database destination (default: `dvr_cases.db`).

---

### 3.5. `dvrft verify`
Verifies block-level BLAKE3 hashes against the initial acquisition manifest to pinpoint localized sector tampering.
```bash
dvrft verify --image C:\Evidence\disk.dd --case-id CASE-2025-01
```
**Example Output**:
```
Integrity Verification Audit:
  Total Blocks Checked: 2,048
  Pristine Blocks     : 2,047
  Tampered Blocks     : 1
    -> Alert: Block at LBA 16384 (Channel 2) modified!
       Expected: a3f89e...
       Actual  : 7b01d4...
```

---

### 3.6. `dvrft carve`
Scans raw unallocated sectors or damaged blocks for H.264 NAL units (SPS `0x67`, PPS `0x68`, IDR `0x65`).
```bash
dvrft carve --image C:\Evidence\disk.dd --case-id CASE-2025-01 --output-dir C:\Evidence\carved\
```

---

### 3.7. `dvrft correlate`
Performs multi-camera temporal-spatial correlation across all parsed streams in a case.
```bash
dvrft correlate --case-id CASE-2025-01 --transition-window 60
```
**Flags & Arguments**:
- `--case-id <STRING>`: Target case identifier.
- `--transition-window <SECS>`: Maximum time window (in seconds) to flag subject transit between camera zones (default: 60s).

---

### 3.8. `dvrft analyze`
Executes visual motion energy estimation and bounding box proposals across recovered video frames.
```bash
dvrft analyze --case-id CASE-2025-01 --threshold 0.15
```
**Flags & Arguments**:
- `--case-id <STRING>`: Target case identifier.
- `--threshold <FLOAT>`: Motion sensitivity cutoff between 0.0 and 1.0 (default: 0.10).

---

### 3.9. `dvrft report`
Compiles all case findings into a court-ready Section 63 BSA PDF certificate, markdown technical report, and extracted video clips.
```bash
dvrft report --case-id CASE-2025-01 --examiner "Dr. A. Sharma" --org "SFSL Cyber Division" --output-dir C:\Evidence\Reports\
```
**Generated Artifacts**:
- `section_63_certificate.pdf`: High-resolution legal certificate with dual hashes, disk geometry, and examiner declarations.
- `forensic_report.md`: Complete audit trail of all parsed channels, carved frames, and anomalies.
- `forensic_report.json`: Machine-readable case JSON.
- `clips/`: Extracted video streams (`channel_1.h264`, `channel_2.h264`).

---

## 4. Desktop Forensic Workstation (GUI)

The platform includes an embedded web GUI that communicates in-process with the Rust engine (zero CLI shelling).

### 4.1. Launching the GUI
Run:
```bash
cargo run -p gui
```
The application starts an HTTP daemon on `http://127.0.0.1:8080` and opens the examiner's default browser.

### 4.2. Workflow Screen Guide

```
+----------------------------------------------------------------------------------+
| [1. ACQUISITION]  [2. IDENTIFY]  [3. PARSE & CARVE]  [4. TIMELINE & AI]  [5. REPORT] |
+----------------------------------------------------------------------------------+
```

1. **Screen 1: Acquisition & Multi-Hashing**
   - Enter source drive/image path and target file.
   - Click **Start Acquisition** to stream bytes with live progress indicators.
   - Displays real-time SHA-256, MD5, and total bytes acquired.
2. **Screen 2: Pre-Acquisition Identification**
   - Click **Run Identification** to scan Sector 0.
   - Displays vendor cards with confidence dials, chipset architecture, and grammar recommendations.
3. **Screen 3: Parse, Descramble & Deep Carving**
   - Select grammar (`C4FS`, `Hikvision`, `Dahua`).
   - Run grammar parsing, toggle WASM descrambling, and execute unallocated sector deep carving.
4. **Screen 4: Multi-Camera Timeline & Visual Analytics**
   - Visualizes multi-camera event chronologies.
   - Highlights camera transitions, motion energy graphs, and synchronous blackout alerts.
5. **Screen 5: Court Reporting & Section 63 BSA Certificate**
   - Fill in Case Number, Forensic Examiner Name, and Laboratory Organization.
   - Click **Generate Legal Certificate & Report** to download the `section_63_certificate.pdf`.

---

## 5. Synthetic Disk Generator (`dvrft-gen`)

For training, bench testing, and mock courtroom simulations, `dvrft-gen` synthesizes forensic test drives:
```bash
dvrft-gen --output test_disk.raw --channels 4 --blocks 16 --scramble --corrupt
```
**Flags**:
- `--channels <N>`: Number of interleaved video channels (default: 4).
- `--blocks <N>`: Number of data blocks to generate.
- `--scramble`: Injects XOR stream scrambling into select blocks.
- `--corrupt`: Injects simulated bad sectors / corrupted block headers to test deep carver recovery.
- Produces `test_disk.raw` alongside `test_disk_ground_truth.json` for validation.
