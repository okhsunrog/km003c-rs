//! Append-only journal that keeps a capture across a crash.
//!
//! Parquet writes its index when the file is closed, so a capture cut short by
//! a crash or a killed app would be unreadable. The recorder therefore appends
//! rows to a journal, flushed after every batch, and converts it once the
//! capture ends. A journal left behind is converted by recovery instead.
//!
//! Layout: [`MAGIC`], the format byte, four strings (output path, model,
//! firmware, serial) as a little-endian `u16` length and UTF-8 bytes, then
//! records of [`ROW_SIZE`] bytes. A crash can cut the last record short; the
//! reader stops before an incomplete record.

use std::fs::{File, TryLockError};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::row::{ROW_SIZE, RecordingRow};
use super::writer::RecordingError;
use super::{RecordingFormat, RecordingMetadata};

const MAGIC: &[u8; 8] = b"KM3CJRN1";
pub(crate) const EXTENSION: &str = "km003c-journal";

/// What the journal is recorded for.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JournalHeader {
    pub(crate) path: PathBuf,
    pub(crate) format: RecordingFormat,
    pub(crate) metadata: RecordingMetadata,
}

impl JournalHeader {
    fn encode(&self) -> Result<Vec<u8>, RecordingError> {
        let path = self
            .path
            .to_str()
            .ok_or_else(|| RecordingError::NonUtf8Path(self.path.clone()))?;
        let mut bytes = MAGIC.to_vec();
        bytes.push(match self.format {
            RecordingFormat::Parquet => 0,
            RecordingFormat::Csv => 1,
        });
        for field in [
            path,
            &self.metadata.model,
            &self.metadata.firmware,
            &self.metadata.serial,
        ] {
            let length = u16::try_from(field.len())
                .map_err(|_| RecordingError::Io(io::Error::other("journal header field is too long")))?;
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        Ok(bytes)
    }

    fn read(reader: &mut impl Read, journal: &Path) -> Result<Self, RecordingError> {
        let invalid = |reason: &str| RecordingError::InvalidJournal {
            path: journal.to_path_buf(),
            reason: reason.to_string(),
        };
        let mut magic = [0; MAGIC.len() + 1];
        reader
            .read_exact(&mut magic)
            .map_err(|_| invalid("the header is incomplete"))?;
        if &magic[..MAGIC.len()] != MAGIC {
            return Err(invalid("the file does not start with the journal signature"));
        }
        let format = match magic[MAGIC.len()] {
            0 => RecordingFormat::Parquet,
            1 => RecordingFormat::Csv,
            _ => return Err(invalid("unknown output format")),
        };
        let mut field = || -> Result<String, RecordingError> {
            let mut length = [0; 2];
            reader
                .read_exact(&mut length)
                .map_err(|_| invalid("the header is incomplete"))?;
            let mut bytes = vec![0; usize::from(u16::from_le_bytes(length))];
            reader
                .read_exact(&mut bytes)
                .map_err(|_| invalid("the header is incomplete"))?;
            String::from_utf8(bytes).map_err(|_| invalid("a header field is not UTF-8"))
        };
        let path = PathBuf::from(field()?);
        let metadata = RecordingMetadata::new(field()?, field()?, field()?);
        Ok(Self { path, format, metadata })
    }
}

pub(crate) struct JournalWriter {
    file: BufWriter<File>,
    path: PathBuf,
    buffer: Vec<u8>,
}

impl JournalWriter {
    /// Create a journal in `dir`, holding an exclusive lock on it so recovery
    /// leaves it alone while the capture runs.
    pub(crate) fn create(dir: &Path, header: &JournalHeader) -> Result<Self, RecordingError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let header = header.encode()?;
        std::fs::create_dir_all(dir)?;
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let path = dir.join(format!(
            "{millis}-{}-{}.{EXTENSION}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = File::create_new(&path)?;
        match file.try_lock() {
            // Some file systems cannot lock; the capture still works.
            Ok(()) | Err(TryLockError::Error(_)) => {}
            Err(TryLockError::WouldBlock) => unreachable!("the journal was just created"),
        }
        let mut file = BufWriter::new(file);
        file.write_all(&header)?;
        file.flush()?;
        Ok(Self {
            file,
            path,
            buffer: Vec::new(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Append rows and hand them to the OS, so a crash of the app loses none.
    pub(crate) fn append(&mut self, rows: &[RecordingRow]) -> io::Result<()> {
        self.buffer.clear();
        for row in rows {
            row.encode(&mut self.buffer);
        }
        self.file.write_all(&self.buffer)?;
        self.file.flush()
    }

    /// Write everything to the storage device.
    pub(crate) fn sync(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.get_ref().sync_data()
    }
}

pub(crate) struct JournalReader {
    reader: BufReader<File>,
    header: JournalHeader,
    finished: bool,
}

impl JournalReader {
    pub(crate) fn new(file: File, path: &Path) -> Result<Self, RecordingError> {
        let mut reader = BufReader::new(file);
        let header = JournalHeader::read(&mut reader, path)?;
        Ok(Self {
            reader,
            header,
            finished: false,
        })
    }

    pub(crate) fn header(&self) -> &JournalHeader {
        &self.header
    }

    /// Up to `max` rows; empty once the complete records are read.
    pub(crate) fn next_chunk(&mut self, max: usize) -> io::Result<Vec<RecordingRow>> {
        let mut rows = Vec::new();
        let mut record = [0; ROW_SIZE];
        while !self.finished && rows.len() < max {
            match read_record(&mut self.reader, &mut record)? {
                true => rows.push(RecordingRow::decode(&record)),
                false => self.finished = true,
            }
        }
        Ok(rows)
    }
}

/// Fill `record`, or return `false` at the end of the file or an incomplete
/// record.
fn read_record(reader: &mut impl Read, record: &mut [u8; ROW_SIZE]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < ROW_SIZE {
        match reader.read(&mut record[filled..]) {
            Ok(0) => return Ok(false),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::row::{RecordingOrigin, test_sample};

    fn header() -> JournalHeader {
        JournalHeader {
            path: PathBuf::from("/tmp/out.parquet"),
            format: RecordingFormat::Csv,
            metadata: RecordingMetadata::new("KM003C", "1.9.9", "007965"),
        }
    }

    #[test]
    fn a_truncated_journal_reads_its_complete_records() {
        let dir = std::env::temp_dir().join(format!("km003c-journal-test-{}", std::process::id()));
        let rows = (0..3)
            .map(|index| {
                RecordingRow::from_sample(test_sample(index * 20_000, 0, 0), RecordingOrigin::default(), index)
            })
            .collect::<Vec<_>>();
        let mut writer = JournalWriter::create(&dir, &header()).unwrap();
        writer.append(&rows).unwrap();
        let path = writer.path().to_path_buf();
        drop(writer);

        // Cut the last record short, as a crash mid-write would.
        let length = std::fs::metadata(&path).unwrap().len();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(length - 10)
            .unwrap();

        let mut reader = JournalReader::new(File::open(&path).unwrap(), &path).unwrap();
        assert_eq!(reader.header(), &header());
        assert_eq!(reader.next_chunk(2).unwrap(), rows[..2]);
        assert!(reader.next_chunk(2).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn other_files_are_not_journals() {
        let path = std::env::temp_dir().join(format!("km003c-not-a-journal-{}", std::process::id()));
        std::fs::write(&path, b"elapsed_us,sample_index\n").unwrap();

        let result = JournalReader::new(File::open(&path).unwrap(), &path);
        assert!(matches!(result, Err(RecordingError::InvalidJournal { .. })));
        std::fs::remove_file(path).unwrap();
    }
}
