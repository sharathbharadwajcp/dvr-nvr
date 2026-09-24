# Standard Operating Procedure (SOP): Digital Video Forensics for CCTV / DVR / NVR Systems

**Document ID**: SOP-DFIR-DVR-001  
**Applicability**: Digital Forensics Laboratories, Law Enforcement Agencies (LEA), Incident Responders  
**Regulatory Framework**: Bharatiya Sakshya Adhiniyam, 2023 (Section 63) & ISO/IEC 27037:2012  
**Platform**: Open Digital Video Forensics Platform (`dvrft` / GUI)  
**Version**: 1.0.0  

---

## 1. Purpose & Scope

This Standard Operating Procedure defines the mandatory, legally sound protocol for seizing, acquiring, parsing, carving, analyzing, and presenting video surveillance evidence recovered from CCTV, DVR, and NVR storage devices.

The procedures outlined ensure:
- Uncompromised evidentiary integrity with zero bit-alteration on physical media.
- Cryptographic verification conforming to statutory chain-of-custody standards.
- Full compliance with Section 63 of the **Bharatiya Sakshya Adhiniyam (BSA), 2023** (formerly Section 65B of the Indian Evidence Act, 1872).

---

## 2. Phase 1: Crime Scene Seizure & Chain of Custody

### 2.1. Physical Assessment & Safety
1. **Photograph the Scene**: Capture high-resolution photographs of the DVR/NVR unit in situ, showing:
   - Front panel status LEDs (Power, HDD, Network, Alarm, Record).
   - Rear panel connections (BNC camera cables, IP ethernet cables, power supply, USB peripherals).
   - Manufacturer model plate, serial number barcode, and MAC address.
2. **Examine Clock Drift**: If the unit display interface is actively running on a monitor, photograph the live system time and compare against an atomic clock (UTC/IST). Record the drift in seconds (e.g., `+184s offset`).
3. **Power Down Protocol**:
   - If the system is locked or password-protected and actively recording, perform a clean shutdown via the interface if accessible.
   - If inaccessible, disconnect the DC power cable from the rear of the DVR (do not shut down power at the main switchboard if other critical equipment is connected).
4. **Disconnection & Labeling**: Label all camera cables with their corresponding channel inputs (e.g., `CH-01 Main Gate`, `CH-02 Lobby`).

### 2.2. Packaging & Sealing
1. Open the DVR chassis in a static-safe area.
2. Note the drive brand, model, serial number, capacity, and interface type (SATA / SAS).
3. Place each hard drive into an anti-static ESD bag.
4. Seal with tamper-evident forensic tape and sign across the seal with the date, time, and Case ID.

---

## 3. Phase 2: Forensic Ingestion & Hardware Write-Blocking

> [!CAUTION]
> Never connect an evidence drive directly to a standard Windows or Linux desktop without a certified hardware write-blocker. Operating systems will silently write volume IDs, mount points, or dirty filesystem bits.

1. Connect the evidence drive to a certified hardware write-blocker (e.g., Tableau T8u Forensic USB 3.0 SATA/IDE Bridge).
2. Connect the write-blocker to the forensic examination workstation.
3. Verify that the hardware write-blocker LED confirms active **Write-Blocked** mode.
4. Verify the host OS detects the drive as read-only.

---

## 4. Phase 3: Bit-Stream Acquisition

The examiner can perform acquisition via the CLI or the Desktop GUI Workstation.

### 4.1. CLI Acquisition
Run `dvrft acquire` specifying the raw device handle and output image path:
```bash
dvrft acquire --source \\.\PhysicalDrive2 --output C:\Evidence\Case2025\disk.dd
```

### 4.2. Ingestion Multi-Hashing
The platform streams data sequentially in 512 KiB blocks, calculating:
- **Whole-Image SHA-256**: Primary cryptographic fingerprint.
- **Whole-Image MD5**: Secondary hash for cross-tool compatibility.
- **Per-Block BLAKE3**: Block-level tree hashes saved to `acquisition_manifest.json` for rapid localized tampering detection.

### 4.3. Manifest Review
Open the generated `acquisition_manifest.json` and confirm:
- `total_bytes` matches drive capacity.
- `sha256` and `md5` are calculated and saved in your physical evidence logbook.

---

## 5. Phase 4: Pre-Acquisition Device Identification

Execute `dvrft identify` to interrogate the disk header:
```bash
dvrft identify --image C:\Evidence\Case2025\disk.dd
```

### 5.1. Interpretation of Results
- **Confidence $\ge 80\%$ (Tier 1 / Tier 2)**: Known signature detected (e.g., `C4FS`, `Hikvision HIKFS`, `Dahua DHFS`). Proceed to Phase 5 parsing.
- **Tier 0 Vendor Match**: Vendor SoC/signature recognized (e.g., CP Plus, Uniview, Matrix, Godrej, TP-Link), but proprietary format requires extension grammar. Consult [vendor-extension-guide.md](file:///C:/Users/HP/.gemini/antigravity/scratch/dvr-forensics/docs/vendor-extension-guide.md) or fallback to Phase 5.3 deep carving.
- **Unrecognized Garbage**: Disk headers may be erased or zeroed. Proceed directly to Phase 5.3 deep carving.

---

## 6. Phase 5: Parsing, Descrambling & Deep Carving

### 6.1. Declarative Grammar Parsing
Parse the disk image into the SQLite investigation case database:
```bash
dvrft parse --image C:\Evidence\Case2025\disk.dd --grammar grammars/dahua-v1.yaml --case-id CASE-2025-09
```

### 6.2. Sandboxed Descrambling
If the grammar identifies scrambled video payloads:
- Ensure the appropriate WASM plugin (`plugins/c4_xor_descrambler.wasm`) is available in the workspace.
- The platform executes the descrambler inside the Wasmtime 24 sandbox with 16 MiB memory ceilings and 500 ms execution epoch watchdog timers.

### 6.3. Deep Frame Carving
For disks with damaged superblocks, wiped partition tables, or deleted video blocks:
```bash
dvrft carve --image C:\Evidence\Case2025\disk.dd --case-id CASE-2025-09 --output-dir C:\Evidence\Case2025\carved
```
The carver extracts H.264 NAL units (Sequence Parameter Sets, Picture Parameter Sets, and IDR/non-IDR slices) directly from unallocated sectors, indexing carved frames into the `frames` database table.

### 6.4. Drive Integrity Verification
Verify block integrity against tampering or bit-rot:
```bash
dvrft verify --image C:\Evidence\Case2025\disk.dd --case-id CASE-2025-09
```

---

## 7. Phase 6: Multi-Camera Timeline Correlation & Visual Analytics

### 7.1. Spatial-Temporal Timeline Correlation
Surveillance installations frequently exhibit clock drift across channels or missing footage during critical incidents. Run cross-camera correlation:
```bash
dvrft correlate --case-id CASE-2025-09
```
This detects:
- **Monotonic Event Fusion**: All camera channels aligned on a single normalized timeline.
- **Cross-Camera Subject Transitions**: Sequence of camera activations within configurable time windows.
- **Synchronous Blackouts**: Coincident drops across multiple camera feeds indicating intentional power disruption or equipment sabotage.

### 7.2. Visual Analytics & Motion Triage
Filter through thousands of hours of static background video:
```bash
dvrft analyze --case-id CASE-2025-09
```
The analytics engine estimates motion energy gradients and proposes entity bounding boxes (`Person`, `Vehicle`, `Face`, `MotionCluster`), assigning relevance scores to prioritize frames containing movement.

---

## 8. Phase 7: Forensic Reporting & Section 63 BSA Certification

### 8.1. Report & Legal Certificate Generation
Generate the formal forensic investigation report and Section 63 BSA certificate:
```bash
dvrft report --case-id CASE-2025-09 --examiner "Dr. A. Sharma, Forensic Analyst" --org "State Forensic Science Laboratory" --output-dir C:\Evidence\Case2025\report
```

### 8.2. Output Deliverables
The reporting crate creates three synchronized deliverables:
1. `section_63_certificate.pdf`: Cryptographically verified legal document formatted in accordance with the Bharatiya Sakshya Adhiniyam, 2023 Section 63 requirements.
2. `forensic_report.md` / `forensic_report.json`: Comprehensive technical logs of every carved stream, block status, and timeline anomaly.
3. `clips/`: Extracted playable `.h264` / `.mp4` video files.

### 8.3. Court Presentation
1. Print and sign the `section_63_certificate.pdf`.
2. Present the certificate alongside physical media custody records.
3. If summoned as an expert witness under Section 39 BSA, 2023, attest to the tool's deterministic multi-hashing and read-only execution.

---

## 9. Phase 8: Evidentiary Archiving

1. Compute SHA-256 hashes of all exported reports, video clips, and database files.
2. Store the primary evidence image and report bundle on write-once optical media (M-DISC Blu-ray) or in a cryptographically sealed digital evidence management system (DEMS).
3. Return the physical evidence drive to the secure evidence vault in accordance with departmental custody protocols.
