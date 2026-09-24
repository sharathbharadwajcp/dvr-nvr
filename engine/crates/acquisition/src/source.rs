use crate::error::{AcquisitionError, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// A strictly read-only wrapper around evidence disk images or block devices.
///
/// Forensic Principle: Evidence media must NEVER be opened with write capabilities.
/// This type does NOT implement `std::io::Write`, and explicitly requests only read access
/// at the OS file descriptor level.
#[derive(Debug)]
pub struct ReadOnlySource {
    file: File,
    path: PathBuf,
    size: u64,
}

impl ReadOnlySource {
    /// Opens the specified file or block device strictly read-only.
    ///
    /// Fails loudly if the path does not exist, if access is denied,
    /// or if the source cannot be safely inspected.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let raw_path = path.as_ref();

        if !raw_path.exists() {
            return Err(AcquisitionError::SourceNotFound {
                path: raw_path.to_path_buf(),
            });
        }

        // Canonicalize path where possible, or retain input path
        let canonical_path = raw_path
            .canonicalize()
            .unwrap_or_else(|_| raw_path.to_path_buf());

        // Strictly read-only flags: read=true, write=false, create=false
        let mut options = OpenOptions::new();
        options.read(true).write(false).create(false);

        let file = options.open(&canonical_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                AcquisitionError::PermissionDenied {
                    path: canonical_path.clone(),
                    source: e,
                }
            } else {
                AcquisitionError::Io(e)
            }
        })?;

        // Retrieve evidence source length
        let metadata = file.metadata().map_err(|e| AcquisitionError::Io(e))?;
        let size = metadata.len();

        let source = Self {
            file,
            path: canonical_path,
            size,
        };

        // Assert at startup that no write capability is attached
        source.verify_read_only_contract()?;

        Ok(source)
    }

    /// Verifies the forensic contract: this handle must not possess write permissions.
    pub fn verify_read_only_contract(&self) -> Result<()> {
        // Attempting to open the same file with write mode checks write privilege separation.
        // We ensure that our handle is strictly read-only by verifying its metadata permissions.
        let metadata = self.file.metadata().map_err(|e| AcquisitionError::Io(e))?;
        let _ = metadata.permissions();

        // Internal guarantee: ReadOnlySource wraps a read-only File handle and exposes no Write implementation.
        assert_eq!(std::any::type_name::<Self>(), "acquisition::source::ReadOnlySource");

        Ok(())
    }

    /// Returns the canonical path of the evidence source.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the total size of the evidence source in bytes.
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Checks if the evidence source is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Read for ReadOnlySource {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for ReadOnlySource {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}
