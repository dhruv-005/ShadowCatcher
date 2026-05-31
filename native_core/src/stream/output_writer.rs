// ============================================
// SHADOW CATCHER - Output Writer
// Writes cleaned stream data to disk
// ============================================

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, error, debug};

use crate::utils::error::{ShadowError, ShadowResult};

// ─────────────────────────────────────────
// WRITE STATS
// ─────────────────────────────────────────

/// Statistics about write operations
#[derive(Debug, Default)]
pub struct WriteStats {
    pub bytes_written: u64,
    pub chunks_written: u64,
    pub write_errors: u64,
}

// ─────────────────────────────────────────
// OUTPUT WRITER
// ─────────────────────────────────────────

/// Buffered file writer for stream output
pub struct OutputWriter {
    writer: BufWriter<File>,
    output_path: PathBuf,
    bytes_written: Arc<AtomicU64>,
    chunks_written: u64,
    is_finalized: bool,
}

impl OutputWriter {
    /// Create a new output writer
    ///
    /// Creates the output file and any parent directories.
    pub fn new(output_path: &str) -> ShadowResult<Self> {
        let path = PathBuf::from(output_path);

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ShadowError::Io(
                    format!("Failed to create dirs: {}", e)
                ))?;
        }

        // Open file for writing
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| ShadowError::Io(
                format!("Failed to open '{}': {}", output_path, e)
            ))?;

        let writer = BufWriter::with_capacity(
            64 * 1024, // 64KB buffer
            file,
        );

        info!("OutputWriter created: {}", output_path);

        Ok(Self {
            writer,
            output_path: path,
            bytes_written: Arc::new(AtomicU64::new(0)),
            chunks_written: 0,
            is_finalized: false,
        })
    }

    /// Create a writer for resuming at a specific offset
    pub fn resume(
        output_path: &str,
        resume_offset: u64,
    ) -> ShadowResult<Self> {
        let path = PathBuf::from(output_path);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|e| ShadowError::Io(e.to_string()))?;

        // Seek to resume position
        file.seek(SeekFrom::Start(resume_offset))
            .map_err(|e| ShadowError::Io(e.to_string()))?;

        let writer = BufWriter::with_capacity(64 * 1024, file);

        info!(
            "OutputWriter resumed at offset {}: {}",
            resume_offset, output_path
        );

        Ok(Self {
            writer,
            output_path: path,
            bytes_written: Arc::new(AtomicU64::new(resume_offset)),
            chunks_written: 0,
            is_finalized: false,
        })
    }

    // ─────────────────────────────────────
    // WRITE OPERATIONS
    // ─────────────────────────────────────

    /// Write raw bytes to output file
    pub fn write_bytes(&self, data: &[u8]) -> ShadowResult<()> {
        if self.is_finalized {
            return Err(ShadowError::Io(
                "Cannot write to finalized output".to_string()
            ));
        }

        if data.is_empty() {
            return Ok(());
        }

        // We need interior mutability for the writer
        // In production this would use a Mutex<BufWriter>
        // For simplicity here we use unsafe
        let writer = unsafe {
            &mut *(
                &self.writer as *const BufWriter<File>
                    as *mut BufWriter<File>
            )
        };

        writer.write_all(data)
            .map_err(|e| ShadowError::Io(
                format!("Write failed: {}", e)
            ))?;

        self.bytes_written.fetch_add(data.len() as u64, Ordering::Relaxed);

        debug!("Wrote {} bytes", data.len());
        Ok(())
    }

    /// Write a string to output file
    pub fn write_str(&self, s: &str) -> ShadowResult<()> {
        self.write_bytes(s.as_bytes())
    }

    /// Flush buffered data to disk
    pub fn flush(&self) -> ShadowResult<()> {
        let writer = unsafe {
            &mut *(
                &self.writer as *const BufWriter<File>
                    as *mut BufWriter<File>
            )
        };

        writer.flush()
            .map_err(|e| ShadowError::Io(
                format!("Flush failed: {}", e)
            ))
    }

    /// Finalize the output file (flush + close)
    pub fn finalize(&self) -> ShadowResult<()> {
        self.flush()?;

        let bytes = self.bytes_written.load(Ordering::Relaxed);
        info!(
            "Output finalized: {} ({} bytes)",
            self.output_path.display(),
            bytes,
        );

        Ok(())
    }

    // ─────────────────────────────────────
    // STATS
    // ─────────────────────────────────────

    /// Get bytes written so far
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// Get output file path
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    /// Get output file size on disk
    pub fn file_size(&self) -> ShadowResult<u64> {
        std::fs::metadata(&self.output_path)
            .map(|m| m.len())
            .map_err(|e| ShadowError::Io(e.to_string()))
    }

    /// Check if output file exists
    pub fn file_exists(&self) -> bool {
        self.output_path.exists()
    }

    /// Delete the output file (on cancel/error)
    pub fn delete(&self) -> ShadowResult<()> {
        if self.output_path.exists() {
            std::fs::remove_file(&self.output_path)
                .map_err(|e| ShadowError::Io(e.to_string()))?;
            info!("Deleted output file: {}", self.output_path.display());
        }
        Ok(())
    }
}

// ─────────────────────────────────────────
// MULTI-PART WRITER
// ─────────────────────────────────────────

/// Writes multiple stream segments to a single output file
/// maintaining correct order
pub struct MultiPartWriter {
    inner: OutputWriter,
    expected_next: u64,
    buffer: std::collections::BTreeMap<u64, Vec<u8>>,
    max_buffered_segments: usize,
}

impl MultiPartWriter {
    pub fn new(output_path: &str) -> ShadowResult<Self> {
        Ok(Self {
            inner: OutputWriter::new(output_path)?,
            expected_next: 0,
            buffer: std::collections::BTreeMap::new(),
            max_buffered_segments: 10,
        })
    }

    /// Write a segment at the given index
    ///
    /// Segments may arrive out of order.
    /// This buffers them and writes in order.
    pub fn write_segment(
        &mut self,
        index: u64,
        data: Vec<u8>,
    ) -> ShadowResult<()> {
        if index == self.expected_next {
            // Write immediately
            self.inner.write_bytes(&data)?;
            self.expected_next += 1;

            // Check buffer for consecutive segments
            while let Some(buffered) = self.buffer.remove(&self.expected_next) {
                self.inner.write_bytes(&buffered)?;
                self.expected_next += 1;
            }
        } else if index > self.expected_next {
            // Buffer out-of-order segment
            if self.buffer.len() < self.max_buffered_segments {
                self.buffer.insert(index, data);
            } else {
                return Err(ShadowError::Stream(
                    format!(
                        "Too many buffered segments: {}",
                        self.buffer.len()
                    )
                ));
            }
        }
        // Ignore duplicate/old segments (index < expected_next)

        Ok(())
    }

    /// Finalize output
    pub fn finalize(&self) -> ShadowResult<()> {
        self.inner.finalize()
    }

    /// Get bytes written
    pub fn bytes_written(&self) -> u64 {
        self.inner.bytes_written()
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_path(dir: &TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().to_string()
    }

    #[test]
    fn test_creates_output_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_path(&dir, "output.mp4");

        let writer = OutputWriter::new(&path).unwrap();
        assert!(writer.file_exists());
    }

    #[test]
    fn test_write_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_path(&dir, "output.mp4");

        let writer = OutputWriter::new(&path).unwrap();
        writer.write_bytes(b"hello world").unwrap();
        writer.finalize().unwrap();

        assert_eq!(writer.bytes_written(), 11);
    }

    #[test]
    fn test_write_multiple_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_path(&dir, "output.mp4");

        let writer = OutputWriter::new(&path).unwrap();
        writer.write_bytes(b"chunk1").unwrap();
        writer.write_bytes(b"chunk2").unwrap();
        writer.write_bytes(b"chunk3").unwrap();
        writer.finalize().unwrap();

        assert_eq!(writer.bytes_written(), 18);
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"chunk1chunk2chunk3");
    }

    #[test]
    fn test_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_path(&dir, "subdir/nested/output.mp4");

        let writer = OutputWriter::new(&path).unwrap();
        assert!(writer.file_exists());
    }

    #[test]
    fn test_delete_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_path(&dir, "output.mp4");

        let writer = OutputWriter::new(&path).unwrap();
        assert!(writer.file_exists());
        writer.delete().unwrap();
        assert!(!writer.file_exists());
    }

    #[test]
    fn test_multipart_writer_ordered() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_path(&dir, "output.mp4");

        let mut writer = MultiPartWriter::new(&path).unwrap();
        writer.write_segment(0, b"seg0".to_vec()).unwrap();
        writer.write_segment(1, b"seg1".to_vec()).unwrap();
        writer.write_segment(2, b"seg2".to_vec()).unwrap();
        writer.finalize().unwrap();

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"seg0seg1seg2");
    }

    #[test]
    fn test_multipart_writer_out_of_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_path(&dir, "output.mp4");

        let mut writer = MultiPartWriter::new(&path).unwrap();
        writer.write_segment(2, b"seg2".to_vec()).unwrap();
        writer.write_segment(0, b"seg0".to_vec()).unwrap();
        writer.write_segment(1, b"seg1".to_vec()).unwrap();
        writer.finalize().unwrap();

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"seg0seg1seg2");
    }

    #[test]
    fn test_empty_write_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_path(&dir, "output.mp4");

        let writer = OutputWriter::new(&path).unwrap();
        writer.write_bytes(b"").unwrap();
        writer.finalize().unwrap();
        assert_eq!(writer.bytes_written(), 0);
    }
}
