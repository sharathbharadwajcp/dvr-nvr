# Vendor Extension Guide: Adding CCTV/DVR/NVR Forensic Grammars

**SIH 2025, Team Cyber 4 — Open Digital Video Forensics Platform for CCTV/DVR/NVR Systems**

---

## 1. Introduction & Anti-Hallucination Policy

The **DVR/NVR Forensic Platform (`dvrft`)** employs a declarative, grammar-driven architecture to acquire, parse, demux, verify, and carve proprietary video evidence across multi-vendor surveillance systems. 

> [!IMPORTANT]
> **Strict Forensic Truthfulness Mandate**:
> We **never invent or guess** filesystem structures, block magic values, or header offsets. 
> Every format supported by the platform must be classified into one of three verifiable **Validation Tiers**:
> - **Tier 1 (Synthetic Fixture)**: Self-authored filesystem layout with 100% deterministic ground truth, used for regression testing and architecture verification.
> - **Tier 2 (Literature-Derived)**: Derived from peer-reviewed academic publications, whitepapers, or published reverse-engineering research without OEM non-disclosure agreements.
> - **Tier 3 (Physical Hardware Confirmed)**: Directly confirmed and extracted from physical CCTV/DVR/NVR appliances in our forensic lab.
>
> If an OEM (e.g. CP Plus, Uniview, Matrix, Godrej, TP-Link) lacks public byte-level documentation, it is maintained in `vendor_registry.yaml` as **Tier 0 (Registry-Only / Unimplemented)** until a verified sample is acquired.

This guide provides a reproducible, step-by-step methodology for forensic analysts and developers to transition a proprietary DVR/NVR storage format from **Tier 0** to **Tier 2** or **Tier 3**.

---

## 2. Phase 1: Physical Acquisition & Test Sample Capture

### Step 1.1: Physical Storage Extraction
1. Disconnect the CCTV/DVR/NVR unit from electrical mains and record serial numbers, model identifiers, and hardware SoC markings on the motherboard (e.g., HiSilicon Hi35xx, Ambarella, Novatek).
2. Remove the internal SATA/NVMe hard drive.
3. Attach the physical drive to a certified hardware write-blocker (e.g., Tableau T8u Forensic USB 3.0 Bridge or Tableau T35u SATA/IDE Bridge).
4. Verify that write-blocking mode is active before connecting to the forensic analysis workstation.

### Step 1.2: Bit-Stream Image Acquisition
Execute `dvrft acquire` to generate a bit-exact, read-only physical raw image alongside SHA-256, MD5, and per-block BLAKE3 hashes:
```bash
dvrft acquire /dev/sdb --case "CASE-OEM-INVESTIGATION-01" --output ./samples/oem_investigation
```

---

## 3. Phase 2: Hex Signature Analysis & Structure Mapping

### Step 2.1: Locate Superblock & Partition Table
Proprietary DVRs frequently avoid standard MBR/GPT partition tables and write directly to raw sectors:
1. Examine Sector 0 (offset `0x00000000`) in a hex viewer (`hexdump -C` or ImHex).
2. Look for vendor brand ASCII strings (e.g., `DHAV`, `HIKFS`, `CPPLUS`, `UNIVIEW`, `SATATYA`, `SEETHRU`, `VIGI`).
3. If Sector 0 is zeroed, scan sector offsets `0x0200` (Sector 1), `0x1000` (4 KiB), or `0x8000` (32 KiB).

### Step 2.2: Identify Interleaved Video Block Geometry
Surveillance DVRs allocate video in fixed-size blocks (commonly 4 KiB, 8 KiB, 32 KiB, or 64 KiB) interleaved across camera channels:
1. Identify repeating header patterns across equidistant offsets.
2. Note the location of:
   - **Magic signature**: 4 to 8 bytes (e.g., `0x44 0x48 0x41 0x56` for DHAV).
   - **Channel ID**: Usually a `uint8`, `uint16_le`, or `uint32_le` near offset `+0x04` or `+0x08`.
   - **Timestamp field**: Usually a Unix `uint32_le` epoch, or a BCD (Binary-Coded Decimal) packed date/time `YYYYMMDDHHMMSS`.
   - **Sequence Number**: Monotonically increasing frame/block index.
   - **Payload Length & Offset**: Start of the raw H.264/H.265 NAL units (`0x00 0x00 0x00 0x01`).

---

## 4. Phase 3: Authoring Declarative YAML Grammar

Create a new grammar file under `grammars/<vendor>-v1.yaml`.

### Grammar Specification Template:
```yaml
grammar:
  id: "oem-vendor-v1"
  name: "OEM Vendor Proprietary Format"
  version: 1
  tier: 2 # 2 = Literature-derived, 3 = Physical hardware confirmed
  vendor: "OEM Brand Name"
  model: "Model Series X"
  chipset: "HiSilicon Hi35xx Architecture"
  # descramble_plugin: "oem_xor_descrambler" # optional WASM descrambler

detection:
  rules:
    - offset: 0
      magic_ascii: "OEM_MAGIC"
      weight: 0.95
    - offset: 512
      magic_ascii: "OEM_SECTOR"
      weight: 0.90

structures:
  superblock:
    offset: 0
    size: 4096
    magic:
      offset: 0
      magic_ascii: "OEM_MAGIC"

  video_block:
    size: 4096
    alignment: 4096
    header:
      magic:
        offset: 0
        magic_ascii: "OEM_MAGIC"
      channel_id:
        offset: 8
        type: uint16_le
      timestamp:
        offset: 12
        type: uint32_le
        format: unix_epoch_seconds
      sequence_num:
        offset: 16
        type: uint32_le
      payload_len:
        offset: 20
        type: uint32_le
      flags:
        offset: 24
        type: uint16_le
    payload:
      offset: 32
      codec: "h264"
```

---

## 5. Phase 4: Sandboxed WASM Descrambling (If Required)

If the vendor scrambles video payload bytes (e.g., bitwise inversion, XOR with key, block rotation):
1. **Never write unsafe host code**. Implement the transformation in a standalone Rust library targeting `wasm32-unknown-unknown`:
   ```rust
   #[no_mangle]
   pub extern "C" fn descramble(ptr: *mut u8, len: usize) -> i32 {
       let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
       for b in slice.iter_mut() {
           *b ^= 0x5A; // Vendor-specific transform
       }
       0 // Success
   }
   ```
2. Compile to WebAssembly:
   ```bash
   cargo build --target wasm32-unknown-unknown --release
   ```
3. Place `<plugin_name>.wasm` into `plugins/` and reference `descramble_plugin: "<plugin_name>"` in the YAML grammar.

---

## 6. Phase 5: Validation Tier Progression

Before submitting a new grammar definition:
1. **Tier 1 (Synthetic)**: Synthesize test fixtures matching the newly drafted grammar using `crates/dvrft-gen` with known ground truth.
2. **Tier 2 (Literature-Derived)**: Document citations, academic research papers, or patent references in `docs/open-gaps.md` and link them in the grammar header.
3. **Tier 3 (Physical Hardware Confirmed)**: Run acquisition and parsing against a physical CCTV test image. Run `dvrft verify` to ensure zero hash discrepancies and verify exported `.mp4` video playback.
4. **Update `vendor_registry.yaml`**: Update the vendor's status from `unimplemented` to `active` and declare its new validation tier.
