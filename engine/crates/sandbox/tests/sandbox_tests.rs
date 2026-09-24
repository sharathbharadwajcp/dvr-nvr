use sandbox::{PluginHost, PluginLimits, SandboxError};
use std::path::PathBuf;

fn get_project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn test_xor_plugin_descrambling() {
    let root = get_project_root();
    let plugin_path = root.join("plugins").join("c4_xor_descrambler.wasm");

    assert!(
        plugin_path.exists(),
        "WASM plugin must exist at: {:?}",
        plugin_path
    );

    let host = PluginHost::new().expect("Failed creating PluginHost");
    let plugin = host
        .load_plugin(&plugin_path, None)
        .expect("Failed loading c4_xor_descrambler.wasm");

    // Reference test data
    let plaintext = b"Digital Video Forensics CCTV Frame Payload SIH 2025 Team Cyber 4";
    let key = [0xD4u8, 0xA8, 0x7E, 0x31];

    let mut scrambled = plaintext.to_vec();
    for (i, byte) in scrambled.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }

    assert_ne!(
        scrambled, plaintext,
        "Scrambled data must differ from plaintext"
    );

    // Call sandboxed descrambler
    let descrambled = plugin
        .descramble(&scrambled)
        .expect("Descramble call must succeed");

    assert_eq!(
        descrambled, plaintext,
        "Descrambled payload must match original plaintext"
    );
}

#[test]
fn test_plugin_timeout_enforcement() {
    let host = PluginHost::new().expect("Failed creating PluginHost");

    // WAT module with an infinite loop in descramble
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "allocate") (param i32) (result i32)
                i32.const 0
            )
            (func (export "descramble") (param i32 i32) (result i32)
                (loop (br 0))
                i32.const 0
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).expect("Failed parsing WAT");

    let limits = PluginLimits {
        max_memory_bytes: 1024 * 1024,
        timeout_ms: 30, // 30ms timeout
    };

    let plugin = host
        .load_plugin_from_bytes(&wasm_bytes, Some(limits))
        .expect("Failed compiling module");

    let start = std::time::Instant::now();
    let result = plugin.descramble(&[1, 2, 3, 4]);
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "Infinite loop plugin must be terminated with an error"
    );

    match result.unwrap_err() {
        SandboxError::ExecutionTimeout(ms) => {
            assert_eq!(ms, 30);
            println!(
                "Timeout correctly enforced after {:.1}ms (configured 30ms)",
                elapsed.as_secs_f64() * 1000.0
            );
        }
        other => panic!("Expected ExecutionTimeout error, got: {:?}", other),
    }
}

#[test]
fn test_plugin_memory_ceiling_enforcement() {
    let host = PluginHost::new().expect("Failed creating PluginHost");

    // Reference module with 1 page (64 KiB) memory
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "allocate") (param i32) (result i32)
                ;; return offset 0
                i32.const 0
            )
            (func (export "descramble") (param i32 i32) (result i32)
                i32.const 0
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).expect("Failed parsing WAT");

    // Set memory limit to 64 KiB (1 page)
    let limits = PluginLimits {
        max_memory_bytes: 65536,
        timeout_ms: 200,
    };

    let plugin = host
        .load_plugin_from_bytes(&wasm_bytes, Some(limits))
        .expect("Failed compiling module");

    // Try to pass a payload of 128 KiB (exceeding the 64 KiB memory ceiling)
    let oversized_payload = vec![0u8; 131072];
    let result = plugin.descramble(&oversized_payload);

    assert!(
        result.is_err(),
        "Oversized buffer exceeding memory ceiling must be rejected"
    );

    match result.unwrap_err() {
        SandboxError::MemoryLimitExceeded(limit) => {
            assert_eq!(limit, 65536);
        }
        other => panic!("Expected MemoryLimitExceeded error, got: {:?}", other),
    }
}
