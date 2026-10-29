use super::RecordingError;
use super::{RecordingFormat, RecordingMetadata};
use crate::offline_view::OfflineRecordingView;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::mpsc;

#[derive(Debug)]
#[non_exhaustive]
pub enum OfflineExportEvent {
    Finished { path: PathBuf, rows: usize },
    Failed(RecordingError),
}

pub struct OfflineExport {
    pub path: PathBuf,
    events: mpsc::UnboundedReceiver<OfflineExportEvent>,
}

impl OfflineExport {
    pub fn start(
        path: PathBuf,
        format: RecordingFormat,
        device: RecordingMetadata,
        view: Arc<OfflineRecordingView>,
    ) -> Result<Self, RecordingError> {
        let (tx, events) = mpsc::unbounded_channel();
        let destination = path.clone();
        let unload_guard = crate::runtime::UnloadGuard::new();
        wasm_bindgen_futures::spawn_local(async move {
            let _unload_guard = unload_guard;
            let result = super::web_export::save_offline(&destination, format, device, &view).await;
            let event = match result {
                Ok(()) => OfflineExportEvent::Finished {
                    path: destination,
                    rows: view.samples.len(),
                },
                Err(error) => OfflineExportEvent::Failed(RecordingError(error)),
            };
            let _ = tx.send(event);
        });
        Ok(Self { path, events })
    }
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
    pub fn poll_event(&mut self) -> Option<OfflineExportEvent> {
        self.events.try_recv().ok()
    }
}
