// Reference WebAssembly Descrambler Plugin for Cyber4 Forensic File System (C4FS v1)
// Implements repeating 4-byte XOR cipher: [0xD4, 0xA8, 0x7E, 0x31]

#[no_mangle]
pub extern "C" fn allocate(size: i32) -> i32 {
    let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr as usize as i32
}

#[no_mangle]
pub extern "C" fn deallocate(ptr: i32, size: i32) {
    if ptr != 0 && size > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(ptr as *mut u8, 0, size as usize);
        }
    }
}

#[no_mangle]
pub extern "C" fn descramble(ptr: i32, len: i32) -> i32 {
    if ptr == 0 || len <= 0 {
        return -1;
    }

    // C4FS XOR key specified in docs/synthetic-format-spec.md Section 4.1
    let key: [u8; 4] = [0xD4, 0xA8, 0x7E, 0x31];

    let slice = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
    for (i, byte) in slice.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }

    0 // Success
}
