# Synthetic DVR Storage Format Specification (C4FS v1)

```
================================================================================
VALIDATION TIER: TIER 1 (Synthetic Ground Truth)
Status: Self-Authored Reference Specification
Target: SIH 2025 Team Cyber 4 Open Digital Video Forensics Platform
================================================================================
```

## 1. Overview
The **Cyber4 Forensic File System (C4FS v1)** is a synthetic vendor-like raw DVR disk format designed for developing and validating forensic acquisition, grammar AST parsing, WASM descrambler plugins, and unallocated video carving.

All multi-byte numeric fields are stored in **Little-Endian** byte order unless explicitly stated. The format operates with fixed-size **4096-byte blocks**.

---

## 2. Disk Layout Map

| Block Index | Byte Offset Range | Structure | Description |
|---|---|---|---|
| **Block 0** | `0x00000000` - `0x00000FFF` | `c4_superblock` | Master volume header & filesystem parameters |
| **Block 1** | `0x00001000` - `0x00001FFF` | `c4_partition_table` | Channel stream definitions and partition bounds |
| **Blocks 2..N** | `0x00002000` - EOF | `c4_video_block` | Interleaved video blocks for Channel A & B |

---

## 3. Data Structures

### 3.1 Superblock (`c4_superblock`) — Block 0 (Offset `0x0000`)
Fixed block size: 4096 bytes.

| Offset | Field | Type | Size | Value / Description |
|---|---|---|---|---|
| `0x0000` | `magic` | `u8[8]` | 8 bytes | `b"C4DVR\x00\x01\x00"` (`[0x43, 0x34, 0x44, 0x56, 0x52, 0x00, 0x01, 0x00]`) |
| `0x0008` | `version` | `u32` | 4 bytes | Format version (`1`) |
| `0x000C` | `block_size` | `u32` | 4 bytes | Block size in bytes (`4096`) |
| `0x0010` | `total_blocks` | `u32` | 4 bytes | Total blocks in the disk image |
| `0x0014` | `partition_table_offset` | `u64` | 8 bytes | Byte offset to partition table (`4096`) |
| `0x001C` | `partition_count` | `u32` | 4 bytes | Number of partitions / channels (`2`) |
| `0x0020` | `created_timestamp` | `u64` | 8 bytes | Creation timestamp (Unix epoch seconds) |
| `0x0028` | `flags` | `u32` | 4 bytes | System flags (default `0`) |
| `0x002C` | `reserved` | `u8[4052]` | 4052 bytes | Zero-padded to 4096 bytes |

---

### 3.2 Partition Table (`c4_partition_table`) — Block 1 (Offset `0x1000`)
Fixed block size: 4096 bytes. Contains partition/stream metadata for each camera channel.

| Offset | Field | Type | Size | Value / Description |
|---|---|---|---|---|
| `0x0000` | `magic` | `u8[4]` | 4 bytes | `b"C4PT"` (`[0x43, 0x34, 0x50, 0x54]`) |
| `0x0004` | `entry_count` | `u32` | 4 bytes | Number of active entries (`2`) |
| `0x0008` | `reserved` | `u8[8]` | 8 bytes | Reserved (`0x00`) |
| `0x0010` | `entries[0]` | `c4_partition_entry` | 32 bytes | Channel 1 (Channel A) entry |
| `0x0030` | `entries[1]` | `c4_partition_entry` | 32 bytes | Channel 2 (Channel B) entry |
| `0x0050` | `padding` | `u8[4016]` | 4016 bytes | Zero-padding to block boundary |

#### Partition Entry Structure (`c4_partition_entry`, 32 bytes)
| Relative Offset | Field | Type | Size | Description |
|---|---|---|---|---|
| `0x00` | `channel_id` | `u32` | 4 bytes | Unique channel identifier (`1` = Ch A, `2` = Ch B) |
| `0x04` | `channel_name` | `u8[8]` | 8 bytes | Null-terminated ASCII name (e.g. `b"CH_01_A\x00"`) |
| `0x0C` | `start_block` | `u32` | 4 bytes | First data block index (`2`) |
| `0x10` | `block_count` | `u32` | 4 bytes | Total stream extent block count |
| `0x14` | `flags` | `u32` | 4 bytes | Status flags (`0x01` = Active, `0x02` = Locked) |
| `0x18` | `reserved` | `u8[8]` | 8 bytes | Zero padding |

---

### 3.3 Video Data Blocks (`c4_video_block`) — Blocks 2..N (Offset `0x2000` onward)
Each block is 4096 bytes, divided into a **32-byte Block Header** and **4064-byte Video Payload**.

#### Video Block Header (32 bytes)
| Relative Offset | Field | Type | Size | Description |
|---|---|---|---|---|
| `0x00` | `magic` | `u8[4]` | 4 bytes | `b"C4VF"` (`[0x43, 0x34, 0x56, 0x46]`) - Cyber4 Video Frame |
| `0x04` | `channel_id` | `u32` | 4 bytes | Originating channel ID (`1` or `2`) |
| `0x08` | `timestamp` | `u64` | 8 bytes | Frame presentation timestamp (Unix epoch seconds) |
| `0x10` | `sequence_num` | `u32` | 4 bytes | Sequential frame counter for this channel |
| `0x14` | `payload_len` | `u32` | 4 bytes | Length of valid video payload in bytes (`4064`) |
| `0x18` | `flags` | `u16` | 2 bytes | Bitmask flags: <br>• `0x0001`: Keyframe (I-Frame)<br>• `0x0002`: Scrambled payload<br>• `0x0004`: Corrupted/Deleted |
| `0x1A` | `header_crc` | `u16` | 2 bytes | Checksum of header bytes `0x00..0x19` |
| `0x1C` | `reserved` | `u32` | 4 bytes | Reserved (0x00000000) |

#### Video Payload (4064 bytes)
- Begins at relative offset `0x20` (byte 32) within the block.
- **Embedded Carving Signature**: The payload always begins with a pseudo-H.264 NAL header: `[0x00, 0x00, 0x00, 0x01, 0x67]` (SPS) or `[0x00, 0x00, 0x00, 0x01, 0x41]` (P-frame) followed by deterministic pseudo-random bytes seeded by `(channel_id * 100000 + sequence_num)`.

---

## 4. Special Forensic Testing Regions

### 4.1 Scrambled Blocks (Plugin Testing)
- Certain blocks have `flags |= 0x0002` (Scrambled).
- The entire 4064-byte payload is XOR-scrambled with a 4-byte repeating key:
  $$\text{XOR Key} = [0xD4, 0xA8, 0x7E, 0x31]$$
- Formula: $\text{byte}[i] = \text{plain}[i] \oplus \text{key}[i \pmod 4]$.
- Used to test the sandboxed WebAssembly descrambler plugin.

### 4.2 Corrupted / Zeroed Headers (Carving Testing)
- In one or more designated blocks, the entire 32-byte header (`0x00..0x1F`) is overwritten with zeroes (`[0x00; 32]`).
- The payload remains intact with the `0x00 00 00 01 67` video signature.
- This represents unallocated or damaged sectors to validate pattern-based frame carving.

---

## 5. Ground-Truth Schema (`synthetic_disk.truth.json`)
The generator emits a JSON sidecar recording:
- `image_metadata`: Total bytes, block size, block count, whole-image SHA-256.
- `channels`: Detailed partition records.
- `blocks`: Array of block descriptors:
  - `block_index`: Linear index on disk.
  - `offset`: Absolute byte offset.
  - `channel_id`: Associated channel (`1` or `2`).
  - `timestamp`: Stored timestamp.
  - `sequence_num`: Sequence counter.
  - `is_scrambled`: Boolean.
  - `xor_key`: Hex string if scrambled (e.g. `"D4A87E31"`).
  - `is_corrupted`: Boolean.
  - `corruption_type`: Description (e.g. `"zeroed_header"`).
  - `payload_hash_blake3`: BLAKE3 hash of the plaintext (unscrambled) payload.
