# Forensic Format Open Gaps & Research Limitations

```
================================================================================
Document: Open Gaps and Ambiguities in Published Research
Project: Open Digital Video Forensics Platform (SIH 2025, Team Cyber 4)
Integrity Principle: Zero-Fabrication Rule (Never guess undocumented offsets)
================================================================================
```

## 1. Overview
In accordance with our non-negotiable architectural principles, we do **not** fabricate byte offsets, field widths, magic signatures, or struct alignments when adding real-vendor grammar formats. If a detail is missing, ambiguous, or incomplete in published academic or forensic literature, it is documented here as an **Open Gap** until validated against physical hardware dumps (TIER 3).

---

## 2. Hikvision DVR File System (HBFS) Gaps

### Primary Citation
> Han, J., Jeong, D., & Lee, S. (2015). *Analysis of the HIKVISION DVR File System*. 7th International Conference on Digital Forensics and Cyber Crime (ICDF2C 2015), LNICST 157, pp. 248–259. Springer, Cham. DOI: 10.1007/978-3-319-25512-5_21.

### Cataloged Gaps:

#### GAP-HIK-01: Master Sector Field Offset Table
* **Issue:** Han et al. (2015, Section 3.1) identify that the Master Sector is located at disk offset `0x200` (512 bytes) and begins with the 18-byte ASCII signature `HIKVISION@HANGZHOU`. The paper enumerates the metadata stored within this 256-byte sector:
  - Total hard disk capacity
  - System log offset and size
  - Video data area offset
  - Data block size
  - Total data block count
  - HIKBTREE index offset and size
  - System initialization timestamp
* **Missing Data:** The published paper does **not** provide a field-by-field byte offset map (e.g., offset `0x12..0x19`, `0x1A..0x21`) or specify bit widths (e.g., whether sector addresses are 32-bit LBAs or 64-bit byte offsets).
* **Resolution Requirement:** Requires acquiring a physical Hikvision DVR drive or raw export (TIER 3) to cross-reference hex offsets against device-reported capacity and timestamps.

#### GAP-HIK-02: Video Block Inner Frame Header Magic
* **Issue:** Han et al. (Section 3.2) explain that video data is stored in large multi-megabyte data blocks whose locations are indexed by the `HIKBTREE`. Within each data block, video is stored as streaming frames.
* **Missing Data:** The paper does not specify the inner frame header signature or frame wrapper magic (e.g., whether frames use a proprietary Hikvision packet header `HKH`, standard PS/TS pack headers `0x000001BA`, or raw H.264/H.265 NAL byte streams `0x00000001`).
* **Resolution Requirement:** Requires carving and analyzing raw data blocks from a real physical Hikvision drive.

#### GAP-HIK-03: HIKBTREE Node Binary Layout & Timestamp Encoding
* **Issue:** Han et al. describe `HIKBTREE` as a B-tree of pages containing time records and block allocation statuses.
* **Missing Data:** The paper is silent on:
  - Node page header format and pointer bit-lengths.
  - Timestamp representation: whether timestamps are standard 32-bit Unix epoch seconds, 64-bit UTC integers, or packed Binary Coded Decimal (BCD).
* **Resolution Requirement:** Needs reverse engineering of a real `HIKBTREE` sector region from physical evidence.

---

## 3. Dahua CCTV Systems (DHFS / DHAV) Gaps

### Primary Citations
> 1. Dragonas, E., Lambrinoudakis, C., & Kotsis, M. (2024). *Forensic analysis of Dahua CCTV systems and artifact interpretation*. Journal of Forensic Sciences.
> 2. FFmpeg Project (2019–2024). *libavformat/dhav.c: Dahua DHAV Demuxer*.

### Cataloged Gaps:

#### GAP-DAH-01: Disk-Level Master Partition Table Location
* **Issue:** While the `DHAV` frame container format is well-documented at the stream level, disk-level filesystem structures (DHFS 4.0 / DHFS 4.1) vary widely across Dahua NVR/DVR models and firmware releases.
* **Missing Data:** The exact sector offset where the DHFS partition superblock is located (e.g., LBA 0 vs LBA 1 vs sector 1024) is not standardized across firmware generations in published literature.
* **Resolution Requirement:** Must be verified on physical Dahua surveillance hard drives across firmware versions.

#### GAP-DAH-02: Date Bitfield Packing
* **Issue:** In the 24-byte DHAV header, the 32-bit date field at offset `0x10` uses bit-packed year/month/day/hour/minute/second representations (Year - 2000 in bits 26..31, Month in bits 22..25, Day in bits 17..21, Hour in bits 12..16, Min in bits 6..11, Sec in bits 0..5).
* **Impact:** Declarative grammars that only support integer scalar reads require bitfield extraction expressions to convert to standard UTC timestamps.
* **Resolution Requirement:** Add bitfield expression support to the grammar DSL in a future iteration.

---

## 4. Summary Table of Validation Tiers

| Format | File | Declared Tier | Basis | Status |
|---|---|---|---|---|
| **C4FS v1** | `grammars/synthetic-v1.yaml` | **TIER 1** | Self-authored reference specification (`docs/synthetic-format-spec.md`) | Fully validated against synthetic ground truth |
| **Hikvision (HBFS)** | `grammars/hikvision-v1.yaml` | **TIER 2** | Han et al. (2015), Section 3 | Compiles; awaiting physical drive image (GAP-HIK-01, GAP-HIK-02) |
| **Dahua (DHAV)** | `grammars/dahua-v1.yaml` | **TIER 2** | Dragonas et al. (2024) & FFmpeg `dhav.c` | Compiles; awaiting physical drive image (GAP-DAH-01) |
