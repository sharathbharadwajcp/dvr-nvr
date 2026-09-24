# DVR Forensic Toolkit: Declarative Grammar Specification (v1)

```
================================================================================
Specification: Declarative Format Grammar DSL
Target: SIH 2025 Team Cyber 4 Open Digital Video Forensics Platform
Schema Version: 1.0
================================================================================
```

## 1. Overview
To avoid hardcoding proprietary CCTV/DVR/NVR filesystem formats into the core engine, formats are declared in human-readable, machine-interpretable **YAML Grammar Files**.

The core engine compiles these grammars into an internal **Abstract Syntax Tree (AST)** and interprets them directly against acquired evidence blocks. Adding support for a new vendor requires only authoring a new grammar file (and optionally a WASM plugin), without recompiling the Rust engine.

---

## 2. Validation Tier Header Requirement
Every grammar file **MUST** declare its validation tier in its header comment:
- `TIER 1`: Validated against synthetic ground truth only.
- `TIER 2`: Derived from cited published research, pending real hardware check.
- `TIER 3`: Validated against physical acquired drive / raw hardware dump.

---

## 3. Grammar Top-Level Schema

```yaml
grammar:
  id: "vendor_format_id"           # Unique slug (e.g., "synthetic-v1", "hikvision-hikbtf")
  name: "Human Readable Name"      # Display name
  version: "1.0"                   # Grammar version
  tier: 1                          # 1, 2, or 3
  description: "Description of format and manufacturer"
  citations:                       # Mandatory for TIER 2
    - "Paper or source link"

detection:
  rules:                           # Rules to auto-detect this format from raw image bytes
    - offset: 0                    # Byte offset in evidence image
      magic_hex: "4334445652000100" # Expected hex bytes
      # OR: magic_ascii: "C4DVR\x00\x01\x00"

structures:
  superblock:
    offset: 0                      # Fixed offset or dynamic expression
    size: 4096                     # Fixed structure size
    fields:
      - name: "magic"
        type: "bytes"
        size: 8
        expected_hex: "4334445652000100"
      - name: "version"
        type: "u32"
        endian: "little"
      - name: "block_size"
        type: "u32"
        endian: "little"
      - name: "total_blocks"
        type: "u32"
        endian: "little"
      - name: "partition_table_offset"
        type: "u64"
        endian: "little"
      - name: "partition_count"
        type: "u32"
        endian: "little"

  partition_table:
    offset: 4096
    size: 4096
    magic:
      offset: 0
      bytes_hex: "43345054"         # "C4PT"
    entries:
      offset: 16
      entry_size: 32
      count_field: "entry_count"   # or fixed integer
      fields:
        - name: "channel_id"
          type: "u32"
          endian: "little"
        - name: "channel_name"
          type: "string"
          size: 8
        - name: "start_block"
          type: "u32"
          endian: "little"
        - name: "block_count"
          type: "u32"
          endian: "little"

  video_block:
    fixed_size: 4096
    header:
      size: 32
      magic:
        offset: 0
        bytes_hex: "43345646"       # "C4VF"
      fields:
        - name: "channel_id"
          type: "u32"
          endian: "little"
          role: "channel_id"        # Standardized semantic role
        - name: "timestamp"
          type: "u64"
          endian: "little"
          role: "timestamp"
          encoding: "unix_seconds"  # unix_seconds | unix_millis | bcd
        - name: "sequence_num"
          type: "u32"
          endian: "little"
          role: "sequence_num"
        - name: "payload_length"
          type: "u32"
          endian: "little"
          role: "payload_length"
        - name: "flags"
          type: "u16"
          endian: "little"
          role: "flags"
          flag_masks:
            keyframe: 0x0001
            scrambled: 0x0002
            corrupted: 0x0004
        - name: "header_crc"
          type: "u16"
          endian: "little"
    payload:
      offset: 32
      length_field: "payload_length"
      default_length: 4064
```

---

## 4. Semantic Roles
To allow downstream tools (demuxers, database storages, carvers) to operate uniformly across any vendor format, field definitions can assign standard semantic `role` attributes:
- `channel_id`: Numeric or identifier of the camera feed.
- `timestamp`: Video frame timestamp (interpreted via `encoding`).
- `sequence_num`: Per-channel monotonic frame sequence index.
- `payload_length`: Length of valid video payload in the block.
- `flags`: Status bitmask (keyframe, scrambled, corrupted).

---

## 5. Minimal Worked Example
Below is a complete, minimal grammar file describing a single-stream format:

```yaml
# VALIDATION TIER: TIER 1 (Synthetic Ground Truth)
grammar:
  id: "minimal-dvr"
  name: "Minimal DVR Stream"
  version: "1.0"
  tier: 1
  description: "Minimal worked example of DVR grammar"

detection:
  rules:
    - offset: 0
      magic_ascii: "MINIDVR1"

structures:
  video_block:
    fixed_size: 2048
    header:
      size: 16
      magic:
        offset: 0
        bytes_ascii: "MFRM"
      fields:
        - name: "channel"
          type: "u16"
          endian: "little"
          role: "channel_id"
        - name: "ts"
          type: "u32"
          endian: "little"
          role: "timestamp"
          encoding: "unix_seconds"
        - name: "size"
          type: "u16"
          endian: "little"
          role: "payload_length"
    payload:
      offset: 16
      length_field: "size"
      default_length: 2032
```
