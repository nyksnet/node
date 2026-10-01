use std::collections::HashMap;
use std::path::PathBuf;

use rand::rng;
use rand::Rng;
use tokio::fs;

use crate::application::loops::sync_loop::SynchronizationBitMask;
use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::block::Block;

/// The state of a rapid block download process.
///
/// Blocks can come in asynchronously and out of order. We need to keep track
/// of which blocks we already processed before starting the rapid block
/// download process, which blocks we received in the course of running the
/// process, and which blocks we have yet to receive.
#[derive(Debug, Clone)]
pub(crate) struct RapidBlockDownload {
    block_storage_dir: PathBuf,
    coverage: SynchronizationBitMask,
    index_to_filename: HashMap<u64, PathBuf>,

    target_height: BlockHeight,

    /// User-specified sync directory, if any.
    sync_dir: Option<PathBuf>,
}

impl RapidBlockDownload {
    /// The base directory for unprocessed blocks.
    ///
    /// Either take the `sync_dir` supplied by the user or, if none, ask the OS for a storage directory. The "base" indicates that the blocks are actually stored in a random subdirectory of this one -- random so as to avoid collisions.
    fn base_storage_dir(sync_dir: &Option<PathBuf>) -> PathBuf {
        if let Some(dir) = sync_dir {
            dir.clone()
        } else {
            let suffix = format!(
                "rapid-block-download-{}/",
                whoami::username().unwrap_or("".to_string())
            );
            std::env::temp_dir().join(suffix)
        }
    }

    /// The target block height we are syncing to.
    pub(crate) fn target(&self) -> BlockHeight {
        self.target_height
    }

    /// Set up a [`RapidBlockDownload`] state.
    pub(crate) async fn new(
        target_height: BlockHeight,
        resume_if_possible: bool,
        sync_dir: Option<PathBuf>,
    ) -> Result<Self, RapidBlockDownloadError> {
        let storage_dir = match Self::try_resume_directory(resume_if_possible, &sync_dir).await {
            Some(d) => d,
            None => {
                tracing::debug!(
                    "No existing storage directory for syncing found, creating new one."
                );
                let storage_dir =
                    Self::base_storage_dir(&sync_dir).join(format!("{}/", rng().next_u64()));
                tokio::fs::create_dir_all(&storage_dir)
                    .await
                    .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
                storage_dir
            }
        };

        let mut index_to_filename = HashMap::new();
        let mut coverage = SynchronizationBitMask::new(1, target_height.next().value());

        // Read and process all the files in the storage directory.
        // There is only something to iterate over if we are resuming from an
        // aborted state.
        let mut number_blocks_recovered = 0;
        let mut entry_iterator = fs::read_dir(&storage_dir)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
        while let Some(entry) = entry_iterator
            .next_entry()
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?
        {
            if let Ok(block) = Self::load_block(&entry.path()).await.inspect_err(|e| {
                tracing::warn!(
                    "Could not read Block from file '{}': {e}",
                    entry.path().to_string_lossy()
                );
            }) {
                let height = block.header().height.value();
                if height >= coverage.upper_bound {
                    coverage = coverage.expand(height + 1);
                }
                coverage.set(height);
                index_to_filename.insert(height, entry.path());
                number_blocks_recovered += 1;
            }
        }
        if number_blocks_recovered != 0 {
            tracing::info!(
                "Resuming sync from previous state with {number_blocks_recovered} stored blocks."
            );
        }

        Ok(Self {
            block_storage_dir: storage_dir,
            coverage,
            index_to_filename,
            target_height,
            sync_dir,
        })
    }

    /// Return the directory used by a previous Rapid Block Download run, if
    /// it was aborted.
    ///
    /// If it was aborted, the files should still be there. No need to download
    /// them again.
    async fn try_resume_directory(
        resume_if_possible: bool,
        sync_dir: &Option<PathBuf>,
    ) -> Option<PathBuf> {
        if !resume_if_possible {
            return None;
        }

        let base_dir = Self::base_storage_dir(sync_dir);
        let mut info = tokio::fs::read_dir(&base_dir)
            .await
            .inspect_err(|e| {
                // Failure to read the directory is a benign error. Likely means
                // that there was no aborted sync to resume from.
                tracing::info!(
                    "Cannot resume sync because directory {} cannot be read: {e}",
                    base_dir.to_string_lossy()
                );
            })
            .ok()?;

        let Some(first_entry) = info
            .next_entry()
            .await
            .inspect_err(|e| {
                // Failure to read the directory is a benign error, but there is
                // no reason why this one would be triggered as opposed to the
                // previous one. Better to log a message just in case.
                tracing::warn!(
                    "Cannot resume sync because directory {} cannot be read: {e}",
                    base_dir.to_string_lossy()
                );
            })
            .ok()?
        else {
            // Empty storage dir. Fishy because it should have been removed by
            // clean up.
            tracing::warn!(
                "Cannot resume sync because directory {} is empty.",
                base_dir.to_string_lossy()
            );
            return None;
        };

        let file_name = first_entry.file_name();
        let file_name_as_string = file_name
            .clone()
            .into_string()
            .unwrap_or_else(|e| format!("{e:?}"))
            .to_string();

        let metadata = first_entry
            .metadata()
            .await
            .inspect_err(|e| {
                // First entry exists but cannot get metadata. Error.
                tracing::warn!(
                    "Cannot resume sync because cannot get metadata of first entry '{}' in directory {}. Error: {e}",
                    file_name_as_string,
                    base_dir.to_string_lossy()
                );
            })
            .ok()?;

        if !metadata.is_dir() {
            tracing::warn!(
                "Cannot resume sync because first entry '{}' in directory {} is not a directory.",
                file_name_as_string,
                base_dir.to_string_lossy()
            );
            return None;
        }

        let directory = base_dir.join(file_name);
        tracing::info!(
            "Resuming sync from directory {}.",
            directory.to_string_lossy()
        );
        Some(directory)
    }

    /// Delete the storage directory and its contents.
    pub(crate) async fn clean_up(&self) -> Result<(), Vec<PathBuf>> {
        let mut error_directories = vec![];
        if let Err(e) = tokio::fs::remove_dir_all(self.block_storage_dir.clone()).await {
            tracing::error!(
                "failed to remove storage directory '{}' for rapid block download: {e}",
                self.block_storage_dir.clone().to_string_lossy()
            );
            error_directories.push(self.block_storage_dir.clone());
        }
        let base = Self::base_storage_dir(&self.sync_dir);
        if let Err(e) = tokio::fs::remove_dir(&base).await {
            tracing::warn!(
                "failed to remove storage directory '{}' for rapid block download: {e}",
                base.to_string_lossy()
            );
            error_directories.push(base);
        }

        if error_directories.is_empty() {
            Ok(())
        } else {
            Err(error_directories)
        }
    }

    /// Add one new block to the chain, effectively setting a new tip digest and
    /// bumping the counter by one.
    ///
    /// # Panics
    ///
    ///  - If the height of the new block does not equal current tip height plus
    ///    one.
    pub(crate) async fn extend_chain(
        &mut self,
        new_block: &Block,
    ) -> Result<(), RapidBlockDownloadError> {
        let new_block_height = new_block.header().height;
        assert_eq!(self.target_height.next(), new_block_height);

        self.coverage = self.coverage.clone().expand(new_block_height.value() + 1);

        self.receive_block(new_block).await?;

        self.target_height = self.target_height.next();

        Ok(())
    }

    /// Get the file name for the block.
    fn file_name(&self, block: &Block) -> PathBuf {
        self.block_storage_dir.join(block.hash().to_hex())
    }

    /// Store the block in the storage directory and mark it as received, if it
    /// wasn't received already.
    pub(crate) async fn receive_block(
        &mut self,
        block: &Block,
    ) -> Result<(), RapidBlockDownloadError> {
        if !self.coverage.contains(block.header().height.value()) {
            let file_name = self.file_name(block);
            self.store_block(block, &file_name).await?;

            self.index_to_filename
                .insert(block.header().height.value(), file_name);
            self.coverage.set(block.header().height.value());
        }

        Ok(())
    }

    /// Store the block in the storage directory.
    async fn store_block(
        &self,
        block: &Block,
        file_name: &PathBuf,
    ) -> Result<(), RapidBlockDownloadError> {
        let data = bincode::serialize(block)
            .map_err(|e| RapidBlockDownloadError::Serialization(e.to_string()))?;
        tokio::fs::write(file_name, data)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))
    }

    /// Load the block from the storage directory.
    async fn load_block(file_name: &PathBuf) -> Result<Block, RapidBlockDownloadError> {
        let data = tokio::fs::read(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
        let block = bincode::deserialize(&data)
            .map_err(|e| RapidBlockDownloadError::Serialization(e.to_string()))?;
        Ok(block)
    }

    /// Read a block from the storage directory.
    pub(crate) async fn get_received_block(
        &self,
        height: BlockHeight,
    ) -> Result<Block, RapidBlockDownloadError> {
        let file_name = self
            .index_to_filename
            .get(&height.value())
            .ok_or(RapidBlockDownloadError::NotReceived(height))?;

        let block = Self::load_block(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;

        Ok(block)
    }

    /// Get the [`SynchronizationBitMask`] corresponding to covered blocks
    /// (blocks we have, whether cached or in the database). The complement of
    /// this bit mask indicates which blocks we do not yet have.
    pub(crate) fn coverage(&self) -> SynchronizationBitMask {
        self.coverage.clone()
    }

    /// Determine whether all blocks have been received.
    pub(crate) fn is_complete(&self) -> bool {
        self.coverage.is_complete()
    }

    /// Determine whether the given block was received already.
    pub(crate) fn have_received(&self, block_height: BlockHeight) -> bool {
        self.coverage.contains(block_height.value())
    }

    /// Delete the block from the storage dir.
    ///
    /// Saves disk / RAM space. However, according to the bit mask, the block
    /// is there. So things go wrong if you ask for the block (which the bit
    /// mask says is there) and it was deleted. Be careful not to do that.
    pub(crate) async fn delete_block(
        &self,
        height: BlockHeight,
    ) -> Result<(), RapidBlockDownloadError> {
        let file_name = self
            .index_to_filename
            .get(&height.value())
            .ok_or(RapidBlockDownloadError::NotReceived(height))?;
        tokio::fs::remove_file(file_name)
            .await
            .map_err(|e| RapidBlockDownloadError::IO(e.to_string()))?;
        Ok(())
    }

    /// Synchronizes the rapid block download state to the new tip.
    pub(crate) fn fast_forward(&mut self, new_tip_height: BlockHeight) {
        if new_tip_height.value() >= self.coverage.upper_bound {
            self.coverage = self.coverage.clone().expand(new_tip_height.value() + 1);
        }
        if new_tip_height.value() >= self.coverage.lower_bound {
            self.coverage
                .set_range(self.coverage.lower_bound, new_tip_height.value());
        }
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(crate) enum RapidBlockDownloadError {
    #[error("I/O error: {0}")]
    IO(String),
    #[error("Block {0} not received")]
    NotReceived(BlockHeight),
    #[error("Serialization error: {0}")]
    Serialization(String),
}
