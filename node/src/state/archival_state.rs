pub(crate) mod import_blocks_from_files;

use std::ops::DerefMut;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;
use memmap2::MmapOptions;
use num_traits::Zero;
use nyks_consensus::block::block_header::BlockHeader;
use nyks_consensus::block::block_header::BlockHeaderWithBlockHashWitness;
use nyks_consensus::block::block_header::HeaderToBlockHashWitness;
use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::block::block_kernel::BlockKernel;
use nyks_consensus::block::mutator_set_update::MutatorSetUpdate;
use nyks_consensus::block::Block;
use nyks_consensus::mutator_set::addition_record::AdditionRecord;
use nyks_consensus::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use nyks_consensus::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use nyks_consensus::mutator_set::removal_record::RemovalRecord;
use nyks_consensus::network::Network;
use nyks_database::create_db_if_missing;
use nyks_database::storage::storage_schema::traits::*;
use nyks_database::NeptuneLevelDb;
use nyks_database::WriteBatchAsync;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tokio::io::SeekFrom;
use tracing::debug;
use tracing::warn;

use super::shared::new_block_file_is_needed;
use super::StorageVecBase;
use crate::application::config::cli_args::Args;
use crate::application::config::data_directory::DataDirectory;
use crate::state::database::BlockFileLocation;
use crate::state::database::BlockIndexKey;
use crate::state::database::BlockIndexValue;
use crate::state::database::BlockRecord;
use crate::state::database::FileRecord;
use crate::state::database::LastFileRecord;
use crate::util_types::rusty_archival_block_mmr::RustyArchivalBlockMmr;
use crate::util_types::rusty_archival_mutator_set::RustyArchivalMutatorSet;

pub(crate) const BLOCK_INDEX_DB_NAME: &str = "block_index";
pub(crate) const MUTATOR_SET_DIRECTORY_NAME: &str = "mutator_set";
pub(crate) const ARCHIVAL_BLOCK_MMR_DIRECTORY_NAME: &str = "archival_block_mmr";

/// Provides interface to historic blockchain data which consists of
///  * block-data stored in individual files (append-only)
///  * block-index database stored in levelDB
///  * mutator set stored in LevelDB,
///
/// all file operations are async, or async-friendly.
///       see <https://github.com/Neptune-Crypto/neptune-core/issues/75>
pub struct ArchivalState {
    data_dir: DataDirectory,

    /// maps block index key to block index value where key/val pairs can be:
    /// ```ignore
    ///   Block(Digest)        -> Block(Box<BlockRecord>)
    ///   File(u32)            -> File(FileRecord)
    ///   Height(BlockHeight)  -> Height(Vec<Digest>)
    ///   LastFile             -> LastFile(LastFileRecord)
    ///   BlockTipDigest       -> BlockTipDigest(Digest)
    /// ```
    ///
    /// So this is effectively 5 logical indexes.
    pub(crate) block_index_db: NeptuneLevelDb<BlockIndexKey, BlockIndexValue>,

    // The genesis block is stored on the heap, as we would otherwise get stack overflows whenever we instantiate
    // this object in a spawned worker task.
    pub(super) genesis_block: Box<Block>,

    // The archival mutator set is persisted to one database that also records a sync label,
    // which corresponds to the hash of the block to which the mutator set is synced.
    pub(crate) archival_mutator_set: RustyArchivalMutatorSet,

    /// Archival-MMR of the block digests belonging to the canonical chain.
    pub archival_block_mmr: RustyArchivalBlockMmr,

    /// The network that this node is on. Used to simplify method interfaces.
    network: Network,
}

// The only reason we have this `Debug` implementation is that it's required
// for some tracing/logging functionalities.
impl core::fmt::Debug for ArchivalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchivalState")
            .field("data_dir", &self.data_dir)
            .field("block_index_db", &self.block_index_db)
            .field("genesis_block", &self.genesis_block)
            .field("network", &self.network)
            .field("archival_block_mmr", &self.archival_block_mmr)
            .finish()
    }
}

impl ArchivalState {
    /// Create databases for block persistence
    async fn initialize_block_index_database(
        data_dir: &DataDirectory,
    ) -> Result<NeptuneLevelDb<BlockIndexKey, BlockIndexValue>> {
        let block_index_db_dir_path = data_dir.block_index_database_dir_path();
        DataDirectory::create_dir_if_not_exists(&block_index_db_dir_path).await?;

        let block_index = NeptuneLevelDb::<BlockIndexKey, BlockIndexValue>::new(
            &block_index_db_dir_path,
            &create_db_if_missing(),
        )
        .await?;

        Ok(block_index)
    }

    /// Initialize an `ArchivalMutatorSet` by opening or creating its databases.
    async fn initialize_mutator_set(data_dir: &DataDirectory) -> Result<RustyArchivalMutatorSet> {
        let ms_db_dir_path = data_dir.mutator_set_database_dir_path();
        DataDirectory::create_dir_if_not_exists(&ms_db_dir_path).await?;

        let path = ms_db_dir_path.clone();
        let result = NeptuneLevelDb::new(&path, &create_db_if_missing()).await;

        let db = match result {
            Ok(db) => db,
            Err(e) => {
                tracing::error!(
                    "Could not open mutator set database at {}: {e}",
                    ms_db_dir_path.display()
                );
                panic!(
                    "Could not open database; do not know how to proceed. Panicking.\n\
                    If you suspect the database may be corrupted, consider renaming the directory {}\
                     or removing it altogether. Or perhaps a node is already running?",
                    ms_db_dir_path.display()
                );
            }
        };

        let mut archival_set = RustyArchivalMutatorSet::connect(db).await;
        archival_set.restore_or_new().await;

        Ok(archival_set)
    }

    async fn initialize_archival_block_mmr(
        data_dir: &DataDirectory,
    ) -> Result<RustyArchivalBlockMmr> {
        let abmmr_dir_path = data_dir.archival_block_mmr_dir_path();
        DataDirectory::create_dir_if_not_exists(&abmmr_dir_path).await?;

        let path = abmmr_dir_path.clone();
        let result = NeptuneLevelDb::new(&path, &create_db_if_missing()).await;

        let db = match result {
            Ok(db) => db,
            Err(e) => {
                tracing::error!(
                    "Could not open archival MMR database at {}: {e}",
                    abmmr_dir_path.display()
                );
                panic!(
                    "Could not open database; do not know how to proceed. Panicking.\n\
                    If you suspect the database may be corrupted, consider renaming the directory {}\
                     or removing it altogether. Or perhaps a node is already running?",
                     abmmr_dir_path.display()
                );
            }
        };

        let archival_bmmr = RustyArchivalBlockMmr::connect(db).await;

        Ok(archival_bmmr)
    }

    /// Find the path connecting two blocks. Every path involves going down some
    /// number of steps and then going up some number of steps. So this function
    /// returns two lists: the list of down steps and the list of up steps. It
    /// also returns their latest common ancestor.
    ///
    /// # Panics
    ///
    ///  - If there is no path. (Meaning: different genesis blocks.)
    ///  - If the blocks on the path are not stored.
    pub(crate) async fn find_path(
        &self,
        start: Digest,
        stop: Digest,
    ) -> (Vec<Digest>, Digest, Vec<Digest>) {
        // We build two lists, initially populated with the start
        // and stop of the walk. We extend the lists downwards by
        // appending predecessors.
        let mut leaving = vec![start];
        let mut arriving = vec![stop];

        let mut leaving_deepest_block_header = self
            .get_block_header(*leaving.last().unwrap())
            .await
            .unwrap();
        let mut arriving_deepest_block_header = self
            .get_block_header(*arriving.last().unwrap())
            .await
            .unwrap();
        while leaving_deepest_block_header.height != arriving_deepest_block_header.height {
            if leaving_deepest_block_header.height < arriving_deepest_block_header.height {
                arriving.push(arriving_deepest_block_header.prev_block_digest);
                arriving_deepest_block_header = self
                    .get_block_header(arriving_deepest_block_header.prev_block_digest)
                    .await
                    .unwrap();
            } else {
                leaving.push(leaving_deepest_block_header.prev_block_digest);
                leaving_deepest_block_header = self
                    .get_block_header(leaving_deepest_block_header.prev_block_digest)
                    .await
                    .unwrap();
            }
        }

        // Extend both lists until their deepest blocks match.
        while leaving.last().unwrap() != arriving.last().unwrap() {
            let leaving_predecessor = self
                .get_block_header(*leaving.last().unwrap())
                .await
                .unwrap()
                .prev_block_digest;
            leaving.push(leaving_predecessor);
            let arriving_predecessor = self
                .get_block_header(*arriving.last().unwrap())
                .await
                .unwrap()
                .prev_block_digest;
            arriving.push(arriving_predecessor);
        }

        // reformat
        let luca = leaving.pop().unwrap();
        arriving.pop();
        arriving.reverse();

        (leaving, luca, arriving)
    }

    /// Apply all [AdditionRecord]s in the genesis block to the archival mutator
    /// set. Set the sync label to the genesis block hash. Persist.
    async fn populate_archival_mutator_set_with_genesis_block(
        archival_mutator_set: &mut RustyArchivalMutatorSet,
        genesis_block: &Block,
    ) {
        for addition_record in &genesis_block.kernel.body.transaction_kernel.outputs {
            archival_mutator_set.ams_mut().add(addition_record).await;
        }
        let genesis_hash = genesis_block.hash();
        archival_mutator_set.set_sync_label(genesis_hash).await;
        archival_mutator_set.persist().await;
    }

    pub async fn new(data_dir: DataDirectory, genesis_block: Block, cli: &Args) -> Self {
        let mut archival_mutator_set = ArchivalState::initialize_mutator_set(&data_dir)
            .await
            .expect("Must be able to initialize archival mutator set");
        debug!("Got archival mutator set");

        // If archival mutator set is empty, populate it with the addition records from genesis block
        // This assumes genesis block doesn't spend anything -- which it can't so that should be OK.
        // We could have populated the archival mutator set with the genesis block UTXOs earlier in
        // the setup, but we don't have the genesis block in scope before this function, so it makes
        // sense to do it here.
        if archival_mutator_set.ams().aocl.is_empty().await {
            Self::populate_archival_mutator_set_with_genesis_block(
                &mut archival_mutator_set,
                &genesis_block,
            )
            .await;
        }

        let mut archival_block_mmr = ArchivalState::initialize_archival_block_mmr(&data_dir)
            .await
            .expect("Must be able to initialize archival block MMR");
        debug!("Got archival block MMR");

        // Add genesis block digest to archival MMR, if empty.
        if archival_block_mmr.ammr().is_empty().await {
            archival_block_mmr
                .ammr_mut()
                .append(genesis_block.hash())
                .await;
        }

        let block_index_db = ArchivalState::initialize_block_index_database(&data_dir)
            .await
            .expect("Must be able to initialize block index database");
        debug!("Got block index database");

        let network = cli.network;
        let genesis_block = Box::new(genesis_block);

        Self {
            data_dir,
            block_index_db,
            genesis_block,
            archival_mutator_set,
            archival_block_mmr,
            network,
        }
    }

    pub(crate) fn genesis_block(&self) -> &Block {
        &self.genesis_block
    }

    /// Return the number of files used to store the raw blocks.
    #[cfg(test)]
    pub(crate) async fn num_block_files(&self) -> u32 {
        let last_rec = self
            .block_index_db
            .get(BlockIndexKey::LastFile)
            .await
            .map(|x| x.as_last_file_record())
            .unwrap_or_default();
        last_rec.last_file + 1
    }

    /// Return the directory in which the raw blocks are stored.
    #[cfg(test)]
    pub(crate) fn block_dir_path(&self) -> PathBuf {
        self.data_dir.block_dir_path()
    }

    /// Write a block disk, without setting it as tip. The returned (key, value)
    /// pairs must be stored to the block-index database for this block to be
    /// retrievable.
    ///
    /// This function only stores the block to a file. It does not modify any
    /// database. It does, however, read from the block index database.
    ///
    /// The caller should verify that the block is not already stored, otherwise
    /// the block will be stored twice which will lead to inconsistencies.
    async fn store_block(
        self: &mut ArchivalState,
        new_block: &Block,
    ) -> Result<Vec<(BlockIndexKey, BlockIndexValue)>> {
        // abort early if mutator set update is invalid.
        if new_block.mutator_set_update().is_err() {
            bail!("invalid block: could not get mutator set update");
        }

        // Fetch last file record to find disk location to store block.
        // This record must exist in the DB already, unless this is the first block
        // stored on disk.
        let mut last_rec: LastFileRecord = self
            .block_index_db
            .get(BlockIndexKey::LastFile)
            .await
            .map(|x| x.as_last_file_record())
            .unwrap_or_default();

        // Open the file that was last used for storing a block
        let mut block_file_path = self.data_dir.block_file_path(last_rec.last_file);
        let serialized_block: Vec<u8> = bincode::serialize(new_block)?;
        let serialized_block_size: u64 = serialized_block.len() as u64;

        let mut block_file = DataDirectory::open_ensure_parent_dir_exists(&block_file_path).await?;

        // Check if we should use the last file, or we need a new one.
        if new_block_file_is_needed(&block_file, serialized_block_size).await {
            last_rec = LastFileRecord {
                last_file: last_rec.last_file + 1,
            };
            block_file_path = self.data_dir.block_file_path(last_rec.last_file);
            block_file = DataDirectory::open_ensure_parent_dir_exists(&block_file_path).await?;
        }

        debug!("Writing block to: {}", block_file_path.display());
        // Get associated file record from database, otherwise create it
        let file_record_key: BlockIndexKey = BlockIndexKey::File(last_rec.last_file);
        let file_record_value: Option<FileRecord> = self
            .block_index_db
            .get(file_record_key)
            .await
            .map(|x| x.as_file_record());
        let file_record_value: FileRecord = match file_record_value {
            Some(record) => record.add(serialized_block_size, new_block.header()),
            None => {
                assert!(
                    block_file.metadata().await.unwrap().len().is_zero(),
                    "If no file record exists, block file must be empty"
                );
                FileRecord::new(serialized_block_size, new_block.header())
            }
        };

        // Make room in file for mmapping and record where block starts
        let pos = block_file.seek(SeekFrom::End(0)).await.unwrap();
        debug!("Size of file prior to block writing: {}", pos);
        block_file
            .seek(SeekFrom::Current(serialized_block_size as i64 - 1))
            .await
            .unwrap();
        block_file.write_all(&[0]).await.unwrap();
        let file_offset: u64 = block_file
            .seek(SeekFrom::Current(-(serialized_block_size as i64)))
            .await
            .unwrap();
        debug!(
            "New file size: {} bytes",
            block_file.metadata().await.unwrap().len()
        );

        let height_record_key = BlockIndexKey::Height(new_block.header().height);
        let mut blocks_at_same_height: Vec<Digest> =
            match self.block_index_db.get(height_record_key).await {
                Some(rec) => rec.as_height_record(),
                None => vec![],
            };

        // Write to file with mmap, only map relevant part of file into memory
        // we use spawn_blocking to make the blocking mmap async-friendly.
        tokio::task::spawn_blocking(move || {
            let mmap = unsafe {
                MmapOptions::new()
                    .offset(pos)
                    .len(serialized_block_size as usize)
                    .map(&block_file)
                    .unwrap()
            };
            let mut mmap: memmap2::MmapMut = mmap.make_mut().unwrap();
            mmap.deref_mut()[..].copy_from_slice(&serialized_block);

            // Flush the memory-mapped pages to the physical disk.
            // This call will block until the data is safely persisted.
            // This ensures block data is written to the blkXX.dat file before
            // updating the DB.  Otherwise we can have situations where the DB
            // references a block that does not exist on disk.
            mmap.flush().unwrap();
        })
        .await?;

        // Update block index database with newly stored block
        let mut block_index_entries: Vec<(BlockIndexKey, BlockIndexValue)> = vec![];
        let block_record_key: BlockIndexKey = BlockIndexKey::Block(new_block.hash());
        let block_record_value: BlockIndexValue = BlockIndexValue::Block(Box::new(BlockRecord {
            block_header: *new_block.header(),
            file_location: BlockFileLocation {
                file_index: last_rec.last_file,
                offset: file_offset,
                block_length: serialized_block_size as usize,
            },
            block_hash_witness: HeaderToBlockHashWitness::from(new_block),
        }));

        block_index_entries.push((file_record_key, BlockIndexValue::File(file_record_value)));
        block_index_entries.push((block_record_key, block_record_value));

        block_index_entries.push((BlockIndexKey::LastFile, BlockIndexValue::LastFile(last_rec)));
        blocks_at_same_height.push(new_block.hash());
        block_index_entries.push((
            height_record_key,
            BlockIndexValue::Height(blocks_at_same_height),
        ));

        Ok(block_index_entries)
    }

    async fn write_block_internal(&mut self, block: &Block, is_canonical_tip: bool) -> Result<()> {
        let block_is_new = self.get_block_header(block.hash()).await.is_none();
        let mut block_index_entries = if block_is_new {
            self.store_block(block).await?
        } else {
            warn!(
                "Attempted to store block but block was already stored.\nBlock digest: {:x}",
                block.hash()
            );
            vec![]
        };

        // Mark block as tip, conditionally
        if is_canonical_tip {
            block_index_entries.push((
                BlockIndexKey::BlockTipDigest,
                BlockIndexValue::BlockTipDigest(block.hash()),
            ));
        }

        let mut batch = WriteBatchAsync::new();
        for (k, v) in block_index_entries {
            batch.op_write(k, v);
        }

        self.block_index_db.batch_write(batch).await;

        Ok(())
    }

    /// Update all of archival state with a new block which is set as tip.
    ///
    /// May also be used to set the tip back to any earlier block, including the
    /// genesis block. However, a path from the current tip to the new tip must
    /// be known.
    ///
    /// Performs no validation.
    ///
    /// # Panics
    ///
    /// - If the new tip does not have a mutator set update.
    /// - If databases are in an inconsistent state.
    pub(crate) async fn set_new_tip(&mut self, block: &Block) -> Result<()> {
        self.write_block_as_tip(block).await?;
        self.append_to_archival_block_mmr(block).await;
        self.update_mutator_set(block).await?;

        Ok(())
    }

    /// Write a newly found block to database and to disk, without setting it as
    /// tip.
    ///
    /// If block was already written to database, then this is a nop as the old
    /// database entries and block stored on disk are considered valid.
    pub(crate) async fn write_block_not_tip(&mut self, block: &Block) -> Result<()> {
        self.write_block_internal(block, false).await
    }

    /// Write a newly found block to database and to disk, and set it as tip.
    ///
    /// If block was already written to database, then it is only marked as
    /// tip, and no write to disk occurs. Instead, the old block database entry
    /// is assumed to be valid, and so is the block stored on disk.
    async fn write_block_as_tip(&mut self, new_block: &Block) -> Result<()> {
        self.write_block_internal(new_block, true).await
    }

    /// Sets a block as tip for the archival block MMR.
    ///
    /// This method handles reorganizations, but all predecessors of this block
    /// must be known and stored in the block index database for it to work.
    async fn append_to_archival_block_mmr(&mut self, new_block: &Block) {
        #[cfg(test)]
        {
            // In tests you're allowed to set a genesis block with a height
            // different than zero. In such cases, this part of the archival state
            // update cannot work. So we skip it.
            if !self.genesis_block.header().height.is_genesis() {
                return;
            }
        }

        // If the new block is the genesis block, special case and exit early
        if new_block.header().height.is_genesis() {
            let genesis_block_hash = self.genesis_block().hash();
            assert_eq!(genesis_block_hash, new_block.hash(), "Wrong genesis block.");
            if let Some(leaf) = self.archival_block_mmr.ammr().try_get_leaf(0).await {
                assert_eq!(leaf, new_block.hash(), "Corrupt block MMR.");
            } else {
                self.archival_block_mmr
                    .ammr_mut()
                    .append(new_block.hash())
                    .await;
            }
            self.archival_block_mmr
                .ammr_mut()
                .prune_to_num_leafs(1)
                .await;
            return;
        }

        // Roll back to length of parent then add new digest.
        let num_leafs_prior_to_this_block = new_block.header().height.into();
        self.archival_block_mmr
            .ammr_mut()
            .prune_to_num_leafs(num_leafs_prior_to_this_block)
            .await;

        let latest_leaf = self
            .archival_block_mmr
            .ammr()
            .get_latest_leaf()
            .await
            .expect("block MMR must always have at least one leaf");
        if new_block.header().prev_block_digest != latest_leaf {
            let (backwards, _, forwards) = self
                .find_path(latest_leaf, new_block.header().prev_block_digest)
                .await;
            for _ in backwards {
                self.archival_block_mmr
                    .ammr_mut()
                    .remove_last_leaf_async()
                    .await;
            }
            for digest in forwards {
                self.archival_block_mmr.ammr_mut().append(digest).await;
            }
        }

        assert_eq!(
            new_block.header().prev_block_digest,
            self.archival_block_mmr.ammr()
                .get_latest_leaf()
                .await
                .expect("block MMR must always have at least one leaf"),
            "Archival block-MMR must be in a consistent state. Try deleting this database to have it rebuilt."
        );
        self.archival_block_mmr
            .ammr_mut()
            .append(new_block.hash())
            .await;
    }

    async fn get_block_from_block_record(&self, block_record: BlockRecord) -> Result<Block> {
        let block_file_path: PathBuf = self
            .data_dir
            .block_file_path(block_record.file_location.file_index);

        tokio::task::spawn_blocking(move || {
            let block_file = std::fs::File::open(&block_file_path)
                .map_err(|e| anyhow::anyhow!("IO Error while reading '{}': {e}.", block_file_path.to_string_lossy()))?;

            // 1. Get file metadata to find its actual size on disk.
            let metadata = block_file.metadata()?;
            let file_size = metadata.len();

            // 2. validate that the requested slice is within the file's bounds.
            // See: https://github.com/Neptune-Crypto/neptune-core/issues/471
            let requested_end = block_record.file_location.offset
                .saturating_add(block_record.file_location.block_length as u64);

            if requested_end > file_size {
                bail!(
                    "Data corruption: Attempted to read beyond end of file '{}'. (Size: {}, Requested End: {})",
                    block_file_path.display(), file_size, requested_end
                );
            }

            // 3. The slice is valid, so we can safely memory-map it.
            let mmap = unsafe {
                MmapOptions::new()
                    .offset(block_record.file_location.offset)
                    .len(block_record.file_location.block_length)
                    .map(&block_file)?
            };

            // 4. deserialize directly from the validated mmap slice.
            bincode::deserialize(&mmap).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to deserialize block from file {}. Data may be corrupt or incompatible\
                     with current version of nyks-node. Error: {}",
                    block_file_path.display(), e
                )
            })
        })
        .await?
    }

    async fn tip_block_record(&self) -> Option<BlockRecord> {
        let tip_digest = self.block_index_db.get(BlockIndexKey::BlockTipDigest).await;
        let tip_digest: Digest = match tip_digest {
            Some(digest) => digest.as_tip_digest(),
            None => return None,
        };

        self.get_block_record(tip_digest).await
    }

    /// Return the latest block that was stored to disk. If no block has been stored to disk, i.e.
    /// if tip is genesis, then `None` is returned
    async fn get_tip_from_disk(&self) -> Result<Option<Block>> {
        let tip_block_record = self.tip_block_record().await;
        let Some(tip_block_record) = tip_block_record else {
            return Ok(None);
        };

        let block: Block = self.get_block_from_block_record(tip_block_record).await?;

        Ok(Some(block))
    }

    /// Returns the block containing this input. Returns `None` if no canonical
    /// block with this input is known.
    ///
    /// Searches max `max_search_depth` blocks back from tip for a matching
    /// transaction input.
    ///
    /// If `max_search_depth` is set to `None`, then all blocks are searched
    /// until a match is found. A `max_search_depth` of `Some(0)` will only
    /// consider the tip.
    pub(crate) async fn find_canonical_block_with_input(
        &self,
        input: AbsoluteIndexSet,
        max_search_depth: Option<u64>,
    ) -> Option<Block> {
        let tip_height = self.tip_header().await.height.value();

        let end = match max_search_depth {
            Some(num) => tip_height.saturating_sub(num),
            None => 0,
        };

        for block_height in (end..=tip_height).rev() {
            let block = self
                .canonical_block_by_height(block_height.into())
                .await
                .expect("Canonical block with in-range height must exist");
            if block
                .body()
                .transaction_kernel
                .inputs
                .iter()
                .any(|rr| rr.absolute_indices == input)
            {
                return Some(block);
            }
        }

        None
    }

    /// Return latest block from database, or genesis block if no other block
    /// is known.
    pub async fn get_tip(&self) -> Block {
        let lookup_res_info: Option<Block> = self
            .get_tip_from_disk()
            .await
            .expect("Failed to read block from disk");

        match lookup_res_info {
            None => *self.genesis_block.clone(),
            Some(block) => block,
        }
    }

    /// Return the header of tip, without loading a whole block from disk.
    async fn tip_header(&self) -> BlockHeader {
        let tip_digest = self
            .block_index_db
            .get(BlockIndexKey::BlockTipDigest)
            .await
            .unwrap_or_else(|| BlockIndexValue::BlockTipDigest(self.genesis_block().hash()))
            .as_tip_digest();

        self.get_block_header(tip_digest)
            .await
            .expect("Header must be known for tip.")
    }

    /// Return parent of tip block. Returns `None` iff tip is genesis block.
    pub(crate) async fn get_tip_parent(&self) -> Option<Block> {
        let tip_header = self.tip_header().await;
        if tip_header.height.is_genesis() {
            return None;
        }

        let parent = self
            .get_block(tip_header.prev_block_digest)
            .await
            .expect("Fetching indicated block must succeed");

        Some(parent.expect("Indicated block must exist"))
    }

    /// Get the header of the block identified by digest.
    ///
    /// Returns `None` if no block with this digest is known. Returns the
    /// genesis header if the block digest is that of the genesis block.
    pub(crate) async fn get_block_header(&self, block_digest: Digest) -> Option<BlockHeader> {
        let mut ret = self
            .block_index_db
            .get(BlockIndexKey::Block(block_digest))
            .await
            .map(|x| x.as_block_record().block_header);

        // If no block was found, check if digest is genesis digest
        if ret.is_none() && block_digest == self.genesis_block.hash() {
            ret = Some(*self.genesis_block.header());
        }

        ret
    }

    /// Returns the block header with a witness to the block hash if that block
    /// is known.
    ///
    /// Returns `None` if the block is not known *or* if the block is the
    /// genesis block, as the genesis block does not need a witness for its
    /// hash.
    pub(crate) async fn block_header_with_hash_witness(
        &self,
        block_digest: Digest,
    ) -> Option<BlockHeaderWithBlockHashWitness> {
        self.block_index_db
            .get(BlockIndexKey::Block(block_digest))
            .await
            .map(|x| {
                let record = x.as_block_record();
                BlockHeaderWithBlockHashWitness::new(record.block_header, record.block_hash_witness)
            })
    }

    /// Get the block record from the block digest, if it is stored.
    ///
    /// Note that the genesis block is not stored, and so does not have a block
    /// record.
    async fn get_block_record(&self, block_digest: Digest) -> Option<BlockRecord> {
        self.block_index_db
            .get(BlockIndexKey::Block(block_digest))
            .await
            .map(|x| x.as_block_record())
    }

    /// Return the block as identified by its digest.
    ///
    /// Return:
    ///  - `Ok(Some(block))` in case of success.
    ///  - `Ok(None)` if the block does not live in archival state.
    ///  - `Err(_)` if there was a problem reading from archival state.
    pub async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
        let maybe_record = self.get_block_record(block_digest).await;
        let Some(record) = maybe_record else {
            let maybe_genesis_block =
                (self.genesis_block.hash() == block_digest).then_some(*self.genesis_block.clone());
            return Ok(maybe_genesis_block);
        };

        // Fetch block from disk
        let block = self.get_block_from_block_record(record).await?;

        Ok(Some(block))
    }

    /// Return the (block kernel, proof leaf) as identified by block hash.
    ///
    /// The proof leaf is the MAST hash leaf of the proof that is used to
    /// calculate the block hash.
    ///
    /// Return:
    ///  - `Ok(Some((block, None)))` in case of success where the returned block
    ///    *is* the genesis block.
    ///  - `Ok(Some((block, Some(proof_leaf))))` in case of success where the
    ///    returned block is *not* the genesis block.
    ///  - `Ok(None)` if the block does not live in archival state.
    ///  - `Err(_)` if there was a problem reading from archival state.
    pub(crate) async fn get_block_kernel_with_proof_digest(
        &self,
        block_digest: Digest,
    ) -> Result<Option<(BlockKernel, Option<Digest>)>> {
        let maybe_record = self.get_block_record(block_digest).await;
        let Some(record) = maybe_record else {
            let maybe_genesis_block =
                (self.genesis_block.hash() == block_digest).then_some(*self.genesis_block.clone());
            let maybe_genesis_block =
                maybe_genesis_block.map(|genesis| (genesis.kernel.clone(), None));
            return Ok(maybe_genesis_block);
        };

        // Fetch block from disk
        let block = self.get_block_from_block_record(record).await?;

        // Perf: avoid recalculating the proof leaf. Just read it from the
        // block record.
        Ok(Some((
            block.kernel.clone(),
            Some(record.block_hash_witness.proof_leaf()),
        )))
    }

    /// Return the canonical block with the given height. None if no height of
    /// this block is known yet.
    async fn canonical_block_by_height(&self, block_height: BlockHeight) -> Option<Block> {
        let block_hash = self
            .archival_block_mmr
            .ammr()
            .try_get_leaf(block_height.value())
            .await?;
        Some(
            self.get_block(block_hash)
                .await
                .expect("Block loading must work")
                .expect("Canonical block with in-range height must exist"),
        )
    }

    /// Return the digests of the known blocks at a specific height
    pub(crate) async fn block_height_to_block_digests(
        &self,
        block_height: BlockHeight,
    ) -> Vec<Digest> {
        if block_height.is_genesis() {
            vec![self.genesis_block().hash()]
        } else {
            self.block_index_db
                .get(BlockIndexKey::Height(block_height))
                .await
                .map(|x| x.as_height_record())
                .unwrap_or_else(Vec::new)
        }
    }

    /// Returns true if the (block height, block hash) pair represents a block
    /// in the canonical chain.
    pub(crate) async fn is_canonical_block(
        &self,
        block_hash: Digest,
        block_height: BlockHeight,
    ) -> bool {
        let block_height: u64 = block_height.into();
        self.archival_block_mmr
            .ammr()
            .try_get_leaf(block_height)
            .await
            .is_some_and(|canonical_digest_at_this_height| {
                canonical_digest_at_this_height == block_hash
            })
    }

    /// Return a boolean indicating if block belongs to most canonical chain.
    ///
    /// Returns false if either the block is not known, or if it's known but
    /// has been orphaned.
    pub(crate) async fn block_belongs_to_canonical_chain(&self, block_digest: Digest) -> bool {
        let Some(block_header) = self.get_block_header(block_digest).await else {
            return false;
        };

        let block_height: u64 = block_header.height.into();

        self.archival_block_mmr
            .ammr()
            .try_get_leaf(block_height)
            .await
            .is_some_and(|canonical_digest_at_this_height| {
                canonical_digest_at_this_height == block_digest
            })
    }

    /// Return a list of digests of the ancestors to the requested digest. Does not include the input
    /// digest. If no ancestors can be found, returns the empty list. The count is the maximum length
    /// of the returned list. E.g. if the input digest corresponds to height 2 and count is 5, the
    /// returned list will contain the digests of block 1 and block 0 (the genesis block).
    /// The input block must correspond to a known block but it can be the genesis block in which case
    /// the empty list will be returned.
    pub(crate) async fn get_ancestor_block_digests(
        &self,
        block_digest: Digest,
        mut count: usize,
    ) -> Vec<Digest> {
        let input_block_header = self.get_block_header(block_digest).await.unwrap();
        let mut parent_digest = input_block_header.prev_block_digest;
        let mut ret = vec![];
        while let Some(parent) = self.get_block_header(parent_digest).await {
            if count == 0 {
                break;
            }
            ret.push(parent_digest);
            parent_digest = parent.prev_block_digest;
            count -= 1;
        }

        ret
    }

    /// Returns the old mutator set matching the provided digest as well as the
    /// mutator set update required to go from the old state to that in the tip.
    ///
    /// # Warning
    ///
    /// This can be a very expensive function to run if it's called with a high
    /// max search depth, as it loads all the blocks in the search path into
    /// memory. A max search depth of 0 means that only the tip is checked.
    async fn mutator_set_to_tip_internal(
        &mut self,
        old_ms_digest: Digest,
        old_aocl_num_leafs: Option<u64>,
        max_search_depth: usize,
    ) -> Option<(MutatorSetAccumulator, MutatorSetUpdate)> {
        let mut search_depth = 0;
        let mut block_mutations = vec![];

        let mut haystack = self.get_tip().await;
        let mut parent = self.get_tip_parent().await;
        let old_msa = loop {
            let haystack_msa = haystack
                .mutator_set_accumulator_after()
                .expect("Block from state must have mutator set after");
            if haystack_msa.hash() == old_ms_digest {
                break haystack_msa;
            }

            search_depth += 1;

            // Notice that comparing the whole mutator set accumulator and not
            // just its hash allows us to do early return here. Parent == None
            // indicates that we've gone all the way back to genesis, with no
            // match.
            if old_aocl_num_leafs
                .is_some_and(|old_num_leafs| old_num_leafs > haystack_msa.aocl.num_leafs())
                || search_depth > max_search_depth
                || parent.is_none()
            {
                return None;
            }

            let MutatorSetUpdate {
                removals,
                additions,
            } = haystack
                .mutator_set_update()
                .expect("Block from state must have mutator set update");
            block_mutations.push((additions, removals));

            haystack = parent.unwrap();
            parent = self
                .get_block(haystack.header().prev_block_digest)
                .await
                .expect("Must succeed in reading block");
        };

        // The removal records collected above were valid for each block but
        // are in the general case not valid for the `mutator_set` which was
        // given as input to this function. In order to find the right removal
        // records, we, temporarily, roll back the state of the archival mutator
        // set. This allows us to read out MMR-authentication paths from a
        // previous state of the mutator set. It's crucial that these changes
        // are not persisted, as that would leave the archival mutator set in a
        // state incompatible with the tip.
        self.archival_mutator_set.persist().await;
        for (additions, removals) in &block_mutations {
            for rr in removals.iter().rev() {
                self.archival_mutator_set.ams_mut().revert_remove(rr).await;
            }

            for ar in additions.iter().rev() {
                self.archival_mutator_set.ams_mut().revert_add(ar).await;
            }
        }

        let (mut addition_records, mut removal_records): (
            Vec<Vec<AdditionRecord>>,
            Vec<Vec<RemovalRecord>>,
        ) = block_mutations.clone().into_iter().unzip();

        addition_records.reverse();
        removal_records.reverse();

        let addition_records = addition_records.concat();
        let mut removal_records = removal_records.concat();

        let swbf_length = self.archival_mutator_set.ams().chunks.len().await;
        for rr in &mut removal_records {
            let mut removals = vec![];
            for (chkidx, (mp, chunk)) in rr
                .target_chunks
                .chunk_indices_and_membership_proofs_and_leafs_iter_mut()
            {
                if swbf_length <= *chkidx {
                    removals.push(*chkidx);
                } else {
                    *mp = self
                        .archival_mutator_set
                        .ams()
                        .swbf_inactive
                        .prove_membership_async(*chkidx)
                        .await;
                    *chunk = self.archival_mutator_set.ams().chunks.get(*chkidx).await;
                }
            }

            for remove in removals {
                rr.target_chunks.retain(|(x, _)| *x != remove);
            }
        }

        self.archival_mutator_set.drop_unpersisted().await;

        Some((
            old_msa,
            MutatorSetUpdate::new(removal_records, addition_records),
        ))
    }

    /// Returns the old mutator set matching the provided digest as well as the
    /// mutator set update required to go from the old state to that in the tip.
    ///
    /// # Warning
    ///
    /// This can be a very expensive function to run if it's called with a high
    /// max search depth, as it loads all the blocks in the search path into
    /// memory. A max search depth of 0 means that only the tip is checked.
    pub(crate) async fn old_mutator_set_and_mutator_set_update_to_tip(
        &mut self,
        old_mutator_set_digest: Digest,
        max_search_depth: usize,
    ) -> Option<(MutatorSetAccumulator, MutatorSetUpdate)> {
        self.mutator_set_to_tip_internal(old_mutator_set_digest, None, max_search_depth)
            .await
    }

    /// Returns Some(MutatorSetUpdate) if a path could be found from tip to a
    /// block with the indicated mutator set.
    ///
    /// # Warning
    ///
    /// This can be a very expensive function to run if it's called with a high
    /// max search depth, as it loads all the blocks in the search path into
    /// memory. A max search depth of 0 means that only the tip is checked.
    pub(crate) async fn get_mutator_set_update_to_tip(
        &mut self,
        mutator_set: &MutatorSetAccumulator,
        max_search_depth: usize,
    ) -> Option<MutatorSetUpdate> {
        self.mutator_set_to_tip_internal(
            mutator_set.hash(),
            Some(mutator_set.aocl.num_leafs()),
            max_search_depth,
        )
        .await
        .map(|(_, msa)| msa)
    }

    /// Update the archival mutator set with a new block.
    ///
    /// Assumes the block in question has already been stored to the database
    /// (or else it is the genesis block). This function handles rollback of the
    /// mutator set if needed but requires that all blocks that are rolled back
    /// are present in the database. The input block is considered chain tip.
    /// All blocks stored in the database are assumed to be valid. The given
    /// `new_block` is also assumed to be valid. This function will return an
    /// error if the new block does not have a mutator set update.
    ///
    /// # Panics
    ///
    ///  - If the database does not contain rolled back blocks.
    ///  - If there is no path to the new block.
    // Public bc used in benchmarks.
    #[doc(hidden)]
    pub async fn update_mutator_set(&mut self, new_block: &Block) -> Result<()> {
        #[cfg(test)]
        {
            // In tests you're allowed to set a genesis block with a height
            // different than zero. In such cases, this part of the archival state
            // update cannot work. So we skip it.
            if !self.genesis_block.header().height.is_genesis() {
                return Ok(());
            }
        }

        // If new block is genesis block, special case and exit early.
        if new_block.header().height.is_genesis() {
            let genesis_hash = self.genesis_block().hash();
            assert_eq!(genesis_hash, new_block.hash(), "Wrong genesis block.");

            self.archival_mutator_set.ams_mut().clear().await;
            Self::populate_archival_mutator_set_with_genesis_block(
                &mut self.archival_mutator_set,
                new_block,
            )
            .await;

            return Ok(());
        }

        // cannot get the mutator set update from new block, so abort early
        if new_block.mutator_set_update().is_err() {
            bail!("invalid block: could not get mutator set update");
        }

        let (forwards, backwards) = {
            // Get the block digest that the mutator set was most recently synced to
            let ms_block_sync_digest = self.archival_mutator_set.get_sync_label();

            // Find path from mutator set sync digest to new block. Optimize for the common case,
            // where the new block is the child block of block that the mutator set is synced to.
            let (backwards, _luca, forwards) =
                if ms_block_sync_digest == new_block.header().prev_block_digest {
                    // Trivial path
                    (vec![], ms_block_sync_digest, vec![])
                } else {
                    // Non-trivial path from current mutator set sync digest to new block
                    self.find_path(ms_block_sync_digest, new_block.header().prev_block_digest)
                        .await
                };
            let forwards = [forwards, vec![new_block.hash()]].concat();

            (forwards, backwards)
        };

        for digest in backwards {
            // Roll back mutator set
            let rollback_block = self
                .get_block(digest)
                .await
                .expect("Fetching block must succeed")
                .unwrap();

            debug!(
                "Updating mutator set: rolling back block with height {}",
                rollback_block.header().height
            );

            let MutatorSetUpdate {
                additions,
                removals,
            } = rollback_block
                .mutator_set_update()
                .expect("Block from state must have mutator set update");

            // Roll back all removal records contained in block
            for removal_record in &removals {
                self.archival_mutator_set
                    .ams_mut()
                    .revert_remove(removal_record)
                    .await;
            }

            // Roll back all addition records contained in block
            for addition_record in additions.iter().rev() {
                assert!(
                    self.archival_mutator_set
                        .ams_mut()
                        .add_is_reversible(addition_record)
                        .await,
                    "Addition record must be in sync with block being rolled back."
                );
                self.archival_mutator_set
                    .ams_mut()
                    .revert_add(addition_record)
                    .await;
            }
        }

        for digest in forwards {
            // Add block to mutator set
            let apply_forward_block = if digest == new_block.hash() {
                // Avoid reading from disk if block to be applied is the block
                // with which this function is invoked.
                new_block.to_owned()
            } else {
                self.get_block(digest)
                    .await
                    .expect("Fetching block must succeed")
                    .unwrap()
            };
            debug!(
                "Updating mutator set: adding block with height {}.  Mined: {}",
                apply_forward_block.header().height,
                apply_forward_block
                    .kernel
                    .header
                    .timestamp
                    .standard_format()
            );

            let MutatorSetUpdate {
                mut additions,
                mut removals,
            } = apply_forward_block
                .mutator_set_update()
                .expect("Block from state must have mutator set update");
            additions.reverse();
            removals.reverse();

            let mut removals_mutable = removals.iter_mut().collect::<Vec<_>>();

            // Add items, thus adding the output UTXOs to the mutator set
            while let Some(addition_record) = additions.pop() {
                // Batch-update all removal records to keep them valid after next addition
                RemovalRecord::batch_update_from_addition(
                    &mut removals_mutable,
                    &self.archival_mutator_set.ams().accumulator().await,
                );

                // Add the element to the mutator set
                self.archival_mutator_set
                    .ams_mut()
                    .add(&addition_record)
                    .await;
            }

            // Remove items, thus removing the input UTXOs from the mutator set
            self.archival_mutator_set
                .ams_mut()
                .batch_remove(removals)
                .await;
        }

        // Sanity check that archival mutator set has been updated consistently with the new block
        debug!("sanity check: was AMS updated consistently with new block?");
        assert_eq!(
            new_block
                .mutator_set_accumulator_after().unwrap()
                .hash(),
            self.archival_mutator_set.ams().hash().await,
            "Calculated archival mutator set commitment must match that from newly added block. Block Digest: {:?}", new_block.hash()
        );

        // Persist updated mutator set to disk, with sync label
        self.archival_mutator_set
            .set_sync_label(new_block.hash())
            .await;
        self.archival_mutator_set.persist().await;

        Ok(())
    }
}
