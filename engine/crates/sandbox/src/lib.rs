pub mod error;

pub use error::{Result, SandboxError};

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use wasmtime::{Config, Engine, Module, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, Trap};

/// Default memory ceiling for sandboxed plugins (16 MiB).
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 16 * 1024 * 1024;

/// Default execution timeout per block descrambling call (200 milliseconds).
pub const DEFAULT_TIMEOUT_MS: u64 = 200;

/// Resource limit configuration for a sandboxed plugin.
#[derive(Debug, Clone)]
pub struct PluginLimits {
    pub max_memory_bytes: usize,
    pub timeout_ms: u64,
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

/// Internal store state tracking resource limits.
pub struct HostState {
    limits: StoreLimits,
}

impl ResourceLimiter for HostState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: u32,
        desired: u32,
        maximum: Option<u32>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        self.limits.table_growing(current, desired, maximum)
    }
}

/// Host environment managing the Wasmtime engine and epoch ticker.
pub struct PluginHost {
    engine: Engine,
    _ticker_active: Arc<AtomicBool>,
}

impl PluginHost {
    /// Initializes the WebAssembly plugin host with epoch interruption enabled.
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.epoch_interruption(true);

        let engine = Engine::new(&config).map_err(|e| SandboxError::CompilationError(e.to_string()))?;

        // Background epoch ticker: increments engine epoch every 10 milliseconds
        let ticker_active = Arc::new(AtomicBool::new(true));
        let active_clone = ticker_active.clone();
        let engine_clone = engine.clone();

        thread::Builder::new()
            .name("wasm-epoch-ticker".to_string())
            .spawn(move || {
                while active_clone.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(10));
                    engine_clone.increment_epoch();
                }
            })
            .map_err(|e| SandboxError::Other(format!("Failed to spawn epoch ticker thread: {}", e)))?;

        Ok(Self {
            engine,
            _ticker_active: ticker_active,
        })
    }

    /// Loads and compiles a WebAssembly descrambler plugin from disk.
    pub fn load_plugin<P: AsRef<Path>>(
        &self,
        path: P,
        limits: Option<PluginLimits>,
    ) -> Result<DescramblePlugin> {
        let p = path.as_ref();
        if !p.exists() {
            return Err(SandboxError::PluginNotFound(p.to_path_buf()));
        }

        let bytes = std::fs::read(p).map_err(|e| SandboxError::Other(format!("Failed reading plugin: {}", e)))?;
        self.load_plugin_from_bytes(&bytes, limits)
    }

    /// Loads and compiles a WebAssembly descrambler plugin directly from raw bytes.
    pub fn load_plugin_from_bytes(
        &self,
        wasm_bytes: &[u8],
        limits: Option<PluginLimits>,
    ) -> Result<DescramblePlugin> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| SandboxError::CompilationError(e.to_string()))?;

        Ok(DescramblePlugin {
            engine: self.engine.clone(),
            module,
            limits: limits.unwrap_or_default(),
        })
    }
}

/// A loaded, sandboxed descrambler plugin instance.
pub struct DescramblePlugin {
    engine: Engine,
    module: Module,
    limits: PluginLimits,
}

impl DescramblePlugin {
    /// Descrambles a raw byte buffer inside the sandboxed WebAssembly environment.
    ///
    /// Guarantees:
    /// 1. Memory ceiling enforced via `StoreLimits`.
    /// 2. Execution timeout strictly enforced via Wasmtime epoch interruption.
    /// 3. Host process is isolated from guest panics, infinite loops, and traps.
    pub fn descramble(&self, scrambled_payload: &[u8]) -> Result<Vec<u8>> {
        let state = HostState {
            limits: StoreLimitsBuilder::new()
                .memory_size(self.limits.max_memory_bytes)
                .build(),
        };

        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);

        // Epoch deadline: (timeout_ms / 10ms tick), minimum 1 tick
        let ticks = (self.limits.timeout_ms / 10).max(1);
        store.set_epoch_deadline(ticks);

        let instance = wasmtime::Instance::new(&mut store, &self.module, &[])
            .map_err(|e| self.translate_wasm_error(e))?;

        // Resolve required WASM exports
        let allocate = instance
            .get_typed_func::<i32, i32>(&mut store, "allocate")
            .map_err(|_| SandboxError::MissingExport("allocate"))?;

        let descramble = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "descramble")
            .map_err(|_| SandboxError::MissingExport("descramble"))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(SandboxError::MissingExport("memory"))?;

        let len = scrambled_payload.len() as i32;

        // 1. Allocate guest memory
        let guest_ptr = allocate
            .call(&mut store, len)
            .map_err(|e| self.translate_wasm_error(e))?;

        // 2. Write scrambled input into guest memory
        let offset = guest_ptr as usize;
        let mem_slice = memory.data_mut(&mut store);
        if offset + scrambled_payload.len() > mem_slice.len() {
            return Err(SandboxError::MemoryLimitExceeded(self.limits.max_memory_bytes));
        }
        mem_slice[offset..offset + scrambled_payload.len()].copy_from_slice(scrambled_payload);

        // 3. Execute descramble with active epoch deadline
        let ret = descramble
            .call(&mut store, (guest_ptr, len))
            .map_err(|e| self.translate_wasm_error(e))?;

        if ret != 0 {
            return Err(SandboxError::Other(format!(
                "Descrambler plugin returned non-zero error code: {}",
                ret
            )));
        }

        // 4. Read descrambled output from guest memory
        let mem_slice = memory.data(&store);
        let result_bytes = mem_slice[offset..offset + scrambled_payload.len()].to_vec();

        // 5. Clean up guest memory if deallocate is exported
        if let Ok(deallocate) = instance.get_typed_func::<(i32, i32), ()>(&mut store, "deallocate") {
            let _ = deallocate.call(&mut store, (guest_ptr, len));
        }

        Ok(result_bytes)
    }

    fn translate_wasm_error(&self, err: anyhow::Error) -> SandboxError {
        if let Some(trap) = err.downcast_ref::<Trap>() {
            if *trap == Trap::Interrupt {
                return SandboxError::ExecutionTimeout(self.limits.timeout_ms);
            }
        }
        let err_str = err.to_string();
        if err_str.contains("interrupt") || err_str.contains("epoch") {
            return SandboxError::ExecutionTimeout(self.limits.timeout_ms);
        }
        if err_str.contains("resource limit") || err_str.contains("memory") {
            return SandboxError::MemoryLimitExceeded(self.limits.max_memory_bytes);
        }
        SandboxError::ExecutionTrap(err_str)
    }
}
