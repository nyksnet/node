use std::collections::VecDeque;

use nyks_consensus::BFieldElement;
use nyks_consensus::block::Block;
use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::block::block_kernel::BlockKernel;
use nyks_consensus::network::Network;
use nyks_consensus::transaction::announcement::Announcement;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::transaction::utxo_triple::UtxoTriple;
use nyks_consensus::twenty_first::tip5::Digest;
use nyks_consensus::twenty_first::util_types::mmr::mmr_trait::Mmr;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_rpc_client::wallet::block::RpcWalletBlock;
use nyks_standards::wallet::allocations::Allocations;
use nyks_standards::wallet::keys::address::Recipient;
use nyks_standards::wallet::keys::viewing_key::Decryptor;
use nyks_standards::wallet::keys::viewing_key::ViewingKey;
use nyks_standards::wallet::notes::content::NoteContent;
use nyks_standards::wallet::notes::content::UtxoContent;
use nyks_standards::wallet::notes::note::Note;
use nyks_standards::wallet::notes::note::PrivateNote;
use nyks_standards::wallet::notes::note::PublicNote;
use thiserror::Error;

use crate::state::utxos::IncomingUtxo;

#[derive(Debug, Copy, Clone, Error)]
pub enum AdvanceError {
    #[error("unrecoverable reorg: chain diverged beyond confirmation window, rescan required")]
    UnrecoverableReorg,

    #[error("chain discontinuity: expected parent {expected}, got {got}")]
    ChainDiscontinuity { expected: Digest, got: Digest },
}

pub struct ChainScanner {
    confirmation_depth: usize,
    /// Height of the last *confirmed* block (i.e. buried > confirmation_depth).
    /// Scan tip = height + confirming_blocks.len().
    pub height: BlockHeight,
    keys: Vec<ViewingKey>,
    confirming_blocks: VecDeque<(Digest, Vec<IncomingUtxo>)>,
    network: Network,
}

impl ChainScanner {
    pub fn new(
        start_height: Option<BlockHeight>,
        confirmation_depth: Option<usize>,
        keys: Vec<ViewingKey>,
        network: Network,
    ) -> Self {
        ChainScanner {
            confirmation_depth: confirmation_depth.unwrap_or(12),
            height: start_height.unwrap_or(BlockHeight::genesis()),
            keys,
            confirming_blocks: VecDeque::new(),
            network,
        }
    }

    pub fn add_key(&mut self, key: ViewingKey) {
        self.keys.push(key);
    }

    pub fn advance(
        &mut self,
        block_batch: &[RpcWalletBlock],
    ) -> Result<Vec<IncomingUtxo>, AdvanceError> {
        if block_batch.is_empty() {
            return Ok(vec![]);
        }

        let mut confirmed = if self.tip_height() == BlockHeight::genesis() {
            self.scan_genesis()
        } else {
            vec![]
        };

        let first_parent = block_batch[0].kernel.header.prev_block_digest;

        if !self.confirming_blocks.is_empty() {
            let is_continuation = self
                .confirming_blocks
                .back()
                .is_some_and(|(h, _)| *h == first_parent);

            if !is_continuation {
                self.handle_reorg(first_parent)?;
            }
        }

        let mut expected_parent = first_parent;

        for block in block_batch {
            let previous = block.kernel.header.prev_block_digest;
            if previous != expected_parent {
                return Err(AdvanceError::ChainDiscontinuity {
                    expected: expected_parent,
                    got: previous,
                });
            }

            let block_hash = block.hash();
            let block_kernel: BlockKernel = block.kernel.clone().into();

            let mut utxos = self.scan_block_for_utxos(block_hash, &block_kernel);
            utxos.extend(self.scan_block_for_guesser_utxos(block_hash, &block_kernel));

            self.confirming_blocks.push_back((block_hash, utxos));
            expected_parent = block_hash;
        }

        confirmed.extend(self.promote_and_cleanup());
        Ok(confirmed)
    }

    /// The block height we have scanned up to (including unconfirmed blocks).
    pub fn tip_height(&self) -> BlockHeight {
        self.height + self.confirming_blocks.len()
    }

    pub fn unconfirmed_balance(&self) -> NativeCurrencyAmount {
        self.confirming_blocks
            .iter()
            .flat_map(|(_, utxos)| utxos.iter())
            .map(|utxo| utxo.utxo.get_native_currency_amount())
            .sum()
    }

    fn scan_genesis(&self) -> Vec<IncomingUtxo> {
        let block = Block::genesis(self.network);
        let allocations = Allocations::genesis(self.network);
        assert_eq!(
            allocations.addition_records(),
            block.all_addition_records().unwrap(),
            "Genesis allocations and block additions differ"
        );

        let sender_randomness = allocations.sender_randomness();
        let block_ref = Some((block.hash(), block.header().height));

        self.keys
            .iter()
            .flat_map(|key| {
                let lock_script_hash = key.address().lock_script().hash();
                let receiver_preimage = key.privacy_preimage();

                allocations
                    .utxos()
                    .enumerate()
                    .filter(move |(_, utxo)| utxo.lock_script_hash() == lock_script_hash)
                    .map(move |(index, utxo)| {
                        IncomingUtxo::new(
                            utxo,
                            sender_randomness,
                            receiver_preimage,
                            index as u64,
                            block_ref,
                        )
                    })
            })
            .collect()
    }

    fn handle_reorg(&mut self, new_parent: Digest) -> Result<(), AdvanceError> {
        match self
            .confirming_blocks
            .iter()
            .position(|(h, _)| *h == new_parent)
        {
            None => {
                // Beyond our window - confirmed height is unaffected; only the
                // unconfirmed window is lost.
                self.confirming_blocks.clear();
                Err(AdvanceError::UnrecoverableReorg)
            }
            Some(pos) => {
                self.confirming_blocks.truncate(pos + 1);
                Ok(())
            }
        }
    }

    fn scan_block_for_utxos(&self, hash: Digest, block_kernel: &BlockKernel) -> Vec<IncomingUtxo> {
        let block_body = &block_kernel.body;
        let transaction_kernel = &block_body.transaction_kernel;
        let outputs_len = transaction_kernel.outputs.len() as u64;
        let base_leaf = block_body.mutator_set_accumulator.aocl.num_leafs() - outputs_len;

        self.scan_announcements(&transaction_kernel.announcements)
            .into_iter()
            .filter_map(|(utxo, sender_randomness, receiver_preimage)| {
                let commitment =
                    UtxoTriple::new(utxo.clone(), sender_randomness, receiver_preimage.hash())
                        .addition_record()
                        .canonical_commitment;
                let index = transaction_kernel
                    .outputs
                    .iter()
                    .position(|r| r.canonical_commitment == commitment)?;

                Some(IncomingUtxo::new(
                    utxo,
                    sender_randomness,
                    receiver_preimage,
                    base_leaf + index as u64,
                    Some((hash, block_kernel.header.height)),
                ))
            })
            .collect()
    }

    /// Scans for guesser (PoW-reward) UTXOs won by one of our own keys.
    ///
    /// Unlike ordinary payments, guesser-fee UTXOs are not delivered via an
    /// encrypted `Announcement`.
    fn scan_block_for_guesser_utxos(
        &self,
        hash: Digest,
        block_kernel: &BlockKernel,
    ) -> Vec<IncomingUtxo> {
        let guesser_utxos = block_kernel.guesser_fee_utxos().unwrap();

        if guesser_utxos.is_empty() {
            return vec![];
        }

        // Guesser-fee UTXOs are appended to the AOCL after the block's ordinary
        // transaction outputs. The block body's AOCL does not yet include these
        // reward UTXOs, so its leaf count is the index of the first guesser-fee UTXO.
        let guesser_base_leaf = block_kernel.body.mutator_set_accumulator.aocl.num_leafs();

        self.keys
            .iter()
            .flat_map(|key| {
                let lock_script_hash = key.address().lock_script().hash();
                let receiver_preimage = key.privacy_preimage();

                guesser_utxos
                    .iter()
                    .enumerate()
                    .filter(move |(_, utxo)| utxo.lock_script_hash() == lock_script_hash)
                    .map(move |(index, utxo)| {
                        IncomingUtxo::new(
                            utxo.clone(),
                            // Guesser-fee UTXOs are a protocol-level reward
                            // rather than a peer-to-peer payment, so there is
                            // no sender randomness to recover - use the
                            // blocks digest.
                            hash,
                            receiver_preimage,
                            guesser_base_leaf + index as u64,
                            Some((hash, block_kernel.header.height)),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn scan_announcements(&self, announcements: &[Announcement]) -> Vec<(Utxo, Digest, Digest)> {
        self.keys
            .iter()
            .flat_map(|key| {
                let receiver_identifier = key.address().receiver_identifier();
                let receiver_preimage = key.privacy_preimage();

                announcements
                    .iter()
                    .filter(|a| extract_receiver_identifier(a) == Some(receiver_identifier))
                    // Malformed / foreign announcements should just get skipped.
                    .filter_map(|a| Note::try_from(a).ok())
                    .filter_map(|note| Self::note_content(key, note))
                    .filter_map(|content| match content {
                        NoteContent::Utxo(UtxoContent {
                            utxo,
                            sender_randomness,
                        }) => Some((utxo, sender_randomness, receiver_preimage)),
                        NoteContent::Message(_) => None,
                    })
                    // A third party can craft a note that decrypts under this key but
                    // whose UTXO isn't actually spendable by us.
                    .filter(|(utxo, _, _)| {
                        utxo.lock_script_hash() == key.address().lock_script().hash()
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Recovers the plaintext [`NoteContent`] of a note, decrypting it first if necessary.
    fn note_content(key: &ViewingKey, note: Note) -> Option<NoteContent> {
        match note {
            // Public notes carry their content in the clear.
            Note::Public(PublicNote { content, .. }) => Some(content),
            // Private notes must be decrypted first, then decoded the same way.
            Note::Private(PrivateNote { ciphertext, .. }) => key.decrypt(&ciphertext).ok(),
        }
    }

    fn promote_and_cleanup(&mut self) -> Vec<IncomingUtxo> {
        let mut confirmed_utxos = Vec::new();

        while self.confirming_blocks.len() > self.confirmation_depth {
            if let Some((_, utxos)) = self.confirming_blocks.pop_front() {
                confirmed_utxos.extend(utxos);
                self.height = self.height + 1;
            }
        }

        confirmed_utxos
    }
}

// A hacky optimization before parsing it into note.
pub fn extract_receiver_identifier(announcement: &Announcement) -> Option<BFieldElement> {
    announcement.message.get(1).copied()
}
