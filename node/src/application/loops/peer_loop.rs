pub(crate) mod channel;

use std::cmp;
use std::marker::Unpin;
use std::net::IpAddr;
use std::time::SystemTime;

use anyhow::bail;
use anyhow::Result;
use bincode::Options;
use futures::sink::Sink;
use futures::sink::SinkExt;
use futures::stream::TryStream;
use futures::stream::TryStreamExt;
use futures::FutureExt;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use libp2p::PeerId;
use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::block::mutator_set_update::MutatorSetUpdate;
use nyks_consensus::block::Block;
use nyks_consensus::block::FUTUREDATING_LIMIT;
use nyks_consensus::consensus_rule_set::ConsensusRuleSet;
use nyks_consensus::mutator_set::removal_record::RemovalRecordValidityError;
use nyks_consensus::proof_abstractions::mast_hash::MastHash;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::transaction_kernel::TransactionConfirmabilityError;
use nyks_consensus::transaction::Transaction;
use nyks_p2p::peer::handshake_data::HandshakeData;
use nyks_p2p::peer::peer_info::PeerConnectionInfo;
use nyks_p2p::peer::peer_info::PeerInfo;
use nyks_p2p::peer::transfer_block::TransferBlock;
use nyks_p2p::peer::BlockProposalRequest;
use nyks_p2p::peer::BlockRequestBatch;
use nyks_p2p::peer::IssuedSyncChallenge;
use nyks_p2p::peer::MutablePeerState;
use nyks_p2p::peer::NegativePeerSanction;
use nyks_p2p::peer::PeerMessage;
use nyks_p2p::peer::PeerSanction;
use nyks_p2p::peer::PeerStanding;
use nyks_p2p::peer::PositivePeerSanction;
use nyks_p2p::peer::SyncChallenge;
use rand::rngs::StdRng;
use rand::RngExt;
use rand::SeedableRng;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tokio::select;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::application::loops::main_loop::MAX_NUM_DIGESTS_IN_BATCH_REQUEST;
use crate::application::loops::peer_loop::channel::MainToPeerTask;
use crate::application::loops::peer_loop::channel::PeerTaskToMain;
use crate::application::loops::peer_loop::channel::PeerTaskToMainTransaction;
use crate::macros::fn_name;
use crate::macros::log_slow_scope;
use crate::state::mempool::MEMPOOL_TX_THRESHOLD_AGE_IN_SECS;
use crate::state::mining::block_proposal::BlockProposalRejectError;
use crate::state::sync_status::SyncStatus;
use crate::state::GlobalState;
use crate::state::GlobalStateLock;

const STANDARD_BLOCK_BATCH_SIZE: usize = 35;
const MINIMUM_BLOCK_BATCH_SIZE: usize = 2;

/// Maximum size in bytes for a single block during fork reconciliation. Blocks
/// larger than this are rejected to prevent RAM exhaustion attacks.
///
/// This constant is defined for the peer to heuristically enforce a safe upper
/// bound as a matter of policy, and does not have to determine which consensus
/// rule set we are on to get an exact value. Note that this policy is only
/// enforced during fork reconciliation -- in particular, it does not contribute
/// to block (in)validity as defined in [`Block::validate`].
const MAX_BLOCK_SIZE_IN_FORK_RECONCILIATION: usize =
    2 * 8 * ConsensusRuleSet::Launch.max_block_size();

/// Maximum size of a single announcement, in BFieldElements. Typical encrypted
/// UTXO notifications are ~400 BFEs. This limit provides headroom while
/// preventing DoS via oversized announcements.
///
/// Note that this limit is enforced as a policy for relaying transactions, and
/// not affect block (in)validity.
pub(crate) const MAX_ANNOUNCEMENT_MESSAGE_SIZE: usize = 4096;

const KEEP_CONNECTION_ALIVE: bool = false;
const DISCONNECT_CONNECTION: bool = true;

pub type PeerStandingNumber = i32;

/// Handles messages from peers via TCP
///
/// also handles messages from main task over the main-to-peer-tasks broadcast
/// channel.
#[derive(Debug)]
pub struct PeerLoopHandler {
    to_main_tx: mpsc::Sender<PeerTaskToMain>,
    global_state_lock: GlobalStateLock,
    peer_id: PeerId,
    peer_address: Multiaddr,
    peer_handshake_data: HandshakeData,
    inbound_connection: bool,
    rng: StdRng,
    #[cfg(test)]
    mock_now: Option<Timestamp>,
}

impl PeerLoopHandler {
    pub(crate) fn new(
        to_main_tx: mpsc::Sender<PeerTaskToMain>,
        global_state_lock: GlobalStateLock,
        peer_id: PeerId,
        peer_address: Multiaddr,
        peer_handshake_data: HandshakeData,
        inbound_connection: bool,
    ) -> Self {
        Self {
            to_main_tx,
            global_state_lock,
            peer_id,
            peer_address,
            peer_handshake_data,
            inbound_connection,
            rng: StdRng::from_rng(&mut rand::rng()),
            #[cfg(test)]
            mock_now: None,
        }
    }

    /// Allows for mocked timestamps such that time dependencies may be tested.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_mocked_time(
        to_main_tx: mpsc::Sender<PeerTaskToMain>,
        global_state_lock: GlobalStateLock,
        peer_id: PeerId,
        peer_address: Multiaddr,
        peer_handshake_data: HandshakeData,
        inbound_connection: bool,
        mocked_time: Timestamp,
    ) -> Self {
        Self {
            to_main_tx,
            global_state_lock,
            peer_id,
            peer_address,
            peer_handshake_data,
            inbound_connection,
            mock_now: Some(mocked_time),
            rng: StdRng::from_rng(&mut rand::rng()),
        }
    }

    /// Overwrite the random number generator object with a specific one.
    ///
    /// Useful for derandomizing tests.
    #[cfg(test)]
    fn set_rng(&mut self, rng: StdRng) {
        self.rng = rng;
    }

    fn now(&self) -> Timestamp {
        #[cfg(not(test))]
        {
            Timestamp::now()
        }
        #[cfg(test)]
        {
            self.mock_now.unwrap_or(Timestamp::now())
        }
    }

    /// Punish a peer for bad behavior.
    ///
    /// Return `Err` if the peer in question is (now) banned.
    ///
    /// # Locking:
    ///   * acquires `global_state_lock` for write
    async fn punish(&mut self, reason: NegativePeerSanction) -> Result<()> {
        let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
        warn!("Punishing peer {} for {:?}", self.peer_id, reason);

        let Some(peer_info) = global_state_mut.net.peer_map.get_mut(&self.peer_id) else {
            bail!("Could not read peer map.");
        };
        debug!("Peer standing before punishment is {}", peer_info.standing);
        let sanction_result = peer_info.standing.sanction(PeerSanction::Negative(reason));
        if let Err(err) = sanction_result {
            warn!("Banning peer: {err}");
            let _ = self
                .to_main_tx
                .send(PeerTaskToMain::Ban(self.peer_id))
                .await;
        }

        sanction_result.map_err(|err| anyhow::anyhow!("Banning peer: {err}"))
    }

    /// Reward a peer for good behavior.
    ///
    /// Return `Err` if the peer in question is banned.
    ///
    /// # Locking:
    ///   * acquires `global_state_lock` for write
    async fn reward(&mut self, reason: PositivePeerSanction) -> Result<()> {
        let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
        debug!("Rewarding peer {} for {:?}", self.peer_id, reason);
        let Some(peer_info) = global_state_mut.net.peer_map.get_mut(&self.peer_id) else {
            error!("Could not read peer map.");
            return Ok(());
        };
        let sanction_result = peer_info.standing.sanction(PeerSanction::Positive(reason));
        if sanction_result.is_err() {
            error!("Cannot reward banned peer");
        }

        sanction_result.map_err(|err| anyhow::anyhow!("Cannot reward banned peer: {err}"))
    }

    /// Construct a batch response, with blocks and their MMR membership proofs
    /// relative to a specified anchor.
    ///
    /// Returns `None` if the anchor has a lower leaf count than the blocks, or
    /// a block height of the response exceeds own tip height.
    async fn batch_response(
        state: &GlobalState,
        blocks: Vec<Block>,
        anchor: &MmrAccumulator,
    ) -> Option<Vec<(TransferBlock, MmrMembershipProof)>> {
        let own_tip_height = state.chain.tip().header().height;
        let block_heights_match_anchor = blocks
            .iter()
            .all(|bl| bl.header().height < anchor.num_leafs().into());
        let block_heights_known = blocks.iter().all(|bl| bl.header().height <= own_tip_height);
        if !block_heights_match_anchor || !block_heights_known {
            let max_block_height = match blocks.iter().map(|bl| bl.header().height).max() {
                Some(height) => height.to_string(),
                None => "None".to_owned(),
            };

            debug!("max_block_height: {max_block_height}");
            debug!("own_tip_height: {own_tip_height}");
            debug!("anchor.num_leafs(): {}", anchor.num_leafs());
            debug!("block_heights_match_anchor: {block_heights_match_anchor}");
            debug!("block_heights_known: {block_heights_known}");
            return None;
        }

        let mut ret = vec![];
        for block in blocks {
            let mmr_mp = state
                .chain
                .archival_state()
                .archival_block_mmr
                .ammr()
                .prove_membership_relative_to_smaller_mmr(
                    block.header().height.into(),
                    anchor.num_leafs(),
                )
                .await;
            let block: TransferBlock = block.try_into().unwrap();
            ret.push((block, mmr_mp));
        }

        Some(ret)
    }

    /// Handle validation and send all blocks to the main task if they're all
    /// valid. Use with a list of blocks or a single block. When the
    /// `received_blocks` is a list, the parent of the `i+1`th block in the
    /// list is the `i`th block. The parent of element zero in this list is
    /// `parent_of_first_block`.
    ///
    /// # Return Value
    ///  - `Err` when the connection should be closed;
    ///  - `Ok(None)` if some block is invalid
    ///  - `Ok(None)` if the last block has insufficient cumulative PoW and we
    ///    are not syncing;
    ///  - `Ok(None)` if the last block has insufficient height and we are
    ///    syncing;
    ///  - `Ok(Some(block_height))` otherwise, referring to the block with the
    ///    highest height in the batch.
    ///
    /// A return value of Ok(Some(_)) means that the message was passed on to
    /// main loop.
    ///
    /// # Locking
    ///   * Acquires `global_state_lock` for write via `self.punish(..)` and
    ///     `self.reward(..)`.
    ///
    /// # Panics
    ///
    ///  - Panics if called with the empty list.
    async fn handle_blocks(
        &mut self,
        received_blocks: Vec<Block>,
        parent_of_first_block: Block,
    ) -> Result<Option<BlockHeight>> {
        debug!(
            "attempting to validate {} {}",
            received_blocks.len(),
            if received_blocks.len() == 1 {
                "block"
            } else {
                "blocks"
            }
        );
        let now = self.now();
        debug!("validating with respect to current timestamp {now}");
        let mut previous_block = &parent_of_first_block;
        for new_block in &received_blocks {
            let new_block_has_proof_of_work = new_block.has_proof_of_work(
                self.global_state_lock.cli().network,
                previous_block.header(),
            );
            debug!("new block has proof of work? {new_block_has_proof_of_work}");
            let new_block_is_valid = new_block
                .is_valid(previous_block, now, self.global_state_lock.cli().network)
                .await;
            debug!("new block is valid? {new_block_is_valid}");
            if !new_block_has_proof_of_work {
                warn!(
                    "Received invalid proof-of-work for block of height {} from peer with IP {}",
                    new_block.kernel.header.height, self.peer_id
                );
                warn!("Difficulty is {}.", previous_block.kernel.header.difficulty);
                warn!(
                    "Proof of work should be {:x} (or more) but was {:x}.",
                    previous_block.kernel.header.difficulty.target(),
                    new_block.hash()
                );
                self.punish(NegativePeerSanction::InvalidBlock((
                    new_block.kernel.header.height,
                    new_block.hash(),
                )))
                .await?;
                warn!("Failed to validate block due to insufficient PoW");
                return Ok(None);
            } else if !new_block_is_valid {
                warn!(
                    "Received invalid block of height {} from peer with IP {}",
                    new_block.kernel.header.height, self.peer_id
                );
                self.punish(NegativePeerSanction::InvalidBlock((
                    new_block.kernel.header.height,
                    new_block.hash(),
                )))
                .await?;
                warn!("Failed to validate block: invalid block");
                return Ok(None);
            }
            debug!(
                "Block with height {} is valid. mined: {}",
                new_block.kernel.header.height,
                new_block.kernel.header.timestamp.standard_format()
            );

            previous_block = new_block;
        }

        // evaluate the fork choice rule
        debug!("Checking last block's canonicity ...");
        let last_block = received_blocks.last().unwrap();
        let is_canonical = self
            .global_state_lock
            .lock_guard()
            .await
            .incoming_block_is_more_canonical(last_block);
        let last_block_height = last_block.header().height;
        if !is_canonical {
            warn!(
                "Received {} blocks from peer but incoming blocks are less \
            canonical than current tip.",
                received_blocks.len()
            );
            return Ok(None);
        }

        // Send the new blocks to the main task which handles the state update
        // and storage to the database.
        let number_of_received_blocks = received_blocks.len();
        self.to_main_tx
            .send(PeerTaskToMain::NewBlocks(received_blocks))
            .await?;
        debug!(
            "Updated block info by block from peer. block height {}",
            last_block_height
        );

        // Valuable, new, hard-to-produce information. Reward peer.
        self.reward(PositivePeerSanction::ValidBlocks(number_of_received_blocks))
            .await?;

        Ok(Some(last_block_height))
    }

    /// Take a single block received from a peer and (attempt to) find a path
    /// between the received block and a common ancestor stored in the blocks
    /// database. Once such a path is found, the list of blocks is passed to
    /// [`Self::handle_blocks`].
    ///
    /// This function attempts to find the parent of the received block, either
    /// by searching the database or by requesting it from a peer.
    ///  - If the parent is not stored, it is requested from the peer and the
    ///    received block is pushed to the fork reconciliation list for later
    ///    handling by this function. The fork reconciliation list starts out
    ///    empty, but grows as more parents are requested and transmitted.
    ///  - If the parent is found in the database, a) block handling continues:
    ///    the entire list of fork reconciliation blocks are passed down the
    ///    pipeline, potentially leading to a state update; and b) the fork
    ///    reconciliation list is cleared.
    ///
    /// # Locking:
    ///
    ///   * Acquires `global_state_lock` for write via `self.punish(..)` and
    ///     `self.reward(..)`.
    ///
    /// # Return Value
    ///
    ///  - Err(_) if something unexpected went wrong.
    ///  - Ok(None) if no state changes were applied, not counting populating
    ///    the `fork_reconciliation_blocks`. This may be due to an error or due
    ///    to not enough information.
    ///  - Ok(Some(block_height)) if a path of blocks was found and found valid
    ///    and passed on to the main loop. In this case, `block_height` is the
    ///    highest block processed.
    async fn try_ensure_path<S>(
        &mut self,
        received_block: Box<Block>,
        peer: &mut S,
        peer_state: &mut MutablePeerState,
    ) -> Result<Option<BlockHeight>>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        // Check block size to prevent RAM exhaustion attacks. Estimate size
        // using bincode serialization which matches network format.
        let block_size = bincode::DefaultOptions::new()
            .serialized_size(received_block.as_ref())
            .unwrap_or(usize::MAX as u64) as usize;

        // Reject individual blocks that are too large
        if block_size > MAX_BLOCK_SIZE_IN_FORK_RECONCILIATION {
            warn!(
                "Received oversized block during fork reconciliation: {} bytes (max: {} bytes)",
                block_size, MAX_BLOCK_SIZE_IN_FORK_RECONCILIATION
            );
            self.punish(NegativePeerSanction::OversizedBlock).await?;
            peer_state.fork_reconciliation_blocks.clear();
            return Ok(None);
        }

        // Does the received block match the fork reconciliation list?
        let received_block_matches_fork_reconciliation_list = if let Some(successor) =
            peer_state.fork_reconciliation_blocks.last()
        {
            let valid = successor
                .is_valid(
                    received_block.as_ref(),
                    self.now(),
                    self.global_state_lock.cli().network,
                )
                .await;
            if !valid {
                warn!(
                        "Fork reconciliation failed after receiving {} blocks: successor of received block is invalid",
                        peer_state.fork_reconciliation_blocks.len() + 1
                    );
            }
            valid
        } else {
            true
        };

        // Are we running out of RAM?
        let too_many_blocks = peer_state.fork_reconciliation_blocks.len() + 1
            >= self.global_state_lock.cli().sync_mode_threshold;
        if too_many_blocks {
            warn!(
                "Fork reconciliation failed after receiving {} blocks: block count exceeds sync mode threshold",
                peer_state.fork_reconciliation_blocks.len() + 1
            );
        }

        // Block mismatch or too many blocks: abort!
        if !received_block_matches_fork_reconciliation_list || too_many_blocks {
            self.punish(NegativePeerSanction::ForkResolutionError((
                received_block.header().height,
                peer_state.fork_reconciliation_blocks.len() as u16,
                received_block.hash(),
            )))
            .await?;
            peer_state.fork_reconciliation_blocks = vec![];
            return Ok(None);
        }

        // otherwise, append
        peer_state.fork_reconciliation_blocks.push(*received_block);

        // Try fetch parent
        let received_block_header = *peer_state
            .fork_reconciliation_blocks
            .last()
            .unwrap()
            .header();

        let parent_digest = received_block_header.prev_block_digest;
        let parent_height = received_block_header.height.previous()
            .expect("transferred block must have previous height because genesis block cannot be transferred");
        debug!("Try ensure path: fetching parent block");
        let parent_block = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .archival_state()
            .get_block(parent_digest)
            .await?;
        debug!(
            "Completed parent block fetching from DB: {}",
            if parent_block.is_some() {
                "found".to_string()
            } else {
                "not found".to_string()
            }
        );

        // If parent is not known (but not genesis) request it.
        let Some(parent_block) = parent_block else {
            if parent_height.is_genesis() {
                peer_state.fork_reconciliation_blocks.clear();
                self.punish(NegativePeerSanction::DifferentGenesis).await?;
                return Ok(None);
            }
            debug!(
                "Parent not known: Requesting previous block with height {} from peer",
                parent_height
            );

            peer.send(PeerMessage::BlockRequestByHash(parent_digest))
                .await?;

            return Ok(None);
        };

        // We want to treat the received fork reconciliation blocks (plus the
        // received block) in reverse order, from oldest to newest, because
        // they were requested from high to low block height.
        let mut new_blocks = peer_state.fork_reconciliation_blocks.clone();
        new_blocks.reverse();

        // Reset the fork resolution state since we got all the way back to a
        // block that we have.
        let fork_reconciliation_event = !peer_state.fork_reconciliation_blocks.is_empty();
        peer_state.fork_reconciliation_blocks.clear();

        let Some(new_block_height) = self.handle_blocks(new_blocks, parent_block).await? else {
            // Handling blocks was unsuccessful. Function `handle_blocks` takes
            // care of punishment. Nothing left to do here but return and keep
            // the connection open.
            return Ok(None);
        };

        // If `BlockNotification` was received during a block reconciliation
        // event, then the peer might have one (or more (unlikely)) blocks that
        // we do not have. We should thus request those blocks.
        if fork_reconciliation_event && peer_state.highest_shared_block_height > new_block_height {
            peer.send(PeerMessage::BlockRequestByHeight(
                peer_state.highest_shared_block_height,
            ))
            .await?;
        }

        Ok(Some(new_block_height))
    }

    /// Handle peer messages and returns Ok(true) if connection should be closed.
    /// Connection should also be closed if an error is returned.
    /// Otherwise, returns OK(false).
    ///
    /// Locking:
    ///   * Acquires `global_state_lock` for read.
    ///   * Acquires `global_state_lock` for write via `self.punish(..)` and
    ///     `self.reward(..)`.
    async fn handle_peer_message<S>(
        &mut self,
        msg: PeerMessage,
        peer: &mut S,
        peer_state_info: &mut MutablePeerState,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        debug!("Received {} from peer {}", msg.get_type(), self.peer_id);
        match msg {
            PeerMessage::Bye => {
                // Note that the current peer is not removed from the global_state.peer_map here
                // but that this is done by the caller.
                info!("Got bye. Closing connection to peer");
                Ok(DISCONNECT_CONNECTION)
            }
            PeerMessage::BlockNotificationRequest => {
                debug!("Got BlockNotificationRequest");

                peer.send(PeerMessage::BlockNotification(
                    self.global_state_lock.lock_guard().await.chain.tip().into(),
                ))
                .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockNotification(block_notification) => {
                const SYNC_CHALLENGE_COOLDOWN: Timestamp = Timestamp::minutes(10);

                let (tip_header, sync_anchor_height) = {
                    let state = self.global_state_lock.lock_guard().await;
                    (
                        *state.chain.tip().header(),
                        state
                            .net
                            .sync_anchor
                            .as_ref()
                            .map(|sync_anchor| sync_anchor.champion.0),
                    )
                };
                debug!(
                    "Got BlockNotification of height {}. Own height is {}",
                    block_notification.height, tip_header.height
                );

                // If we are syncing and:
                if let Some(height) = sync_anchor_height {
                    // - and announced block succeeds sync anchor, then request it;
                    if height.next() == block_notification.height {
                        peer.send(PeerMessage::BlockRequestByHeight(block_notification.height))
                            .await?;
                    }
                    // - otherwise, ignore it.
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Issue challenge if appropriate.
                let sync_mode_threshold = self.global_state_lock.cli().sync_mode_threshold;
                let now = self.now();
                let time_since_latest_successful_challenge = peer_state_info
                    .successful_sync_challenge_response_time
                    .map(|then| now - then);
                let cooldown_expired = time_since_latest_successful_challenge
                    .is_none_or(|time_passed| time_passed > SYNC_CHALLENGE_COOLDOWN);
                let claimed_height_and_pow_exceed_sync_mode_threshold =
                    GlobalState::sync_mode_threshold_stateless(
                        &tip_header,
                        block_notification.height,
                        block_notification.cumulative_proof_of_work,
                        sync_mode_threshold,
                    );
                if cooldown_expired && claimed_height_and_pow_exceed_sync_mode_threshold {
                    debug!("sync mode criterion satisfied.");

                    if peer_state_info.sync_challenge.is_some() {
                        warn!("Cannot launch new sync challenge because one is already on-going.");
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }

                    info!(
                        "Peer indicates block which satisfies sync mode criterion, issuing challenge."
                    );
                    let challenge = SyncChallenge::generate(
                        &block_notification,
                        tip_header.height,
                        self.rng.random(),
                    );
                    peer_state_info.sync_challenge = Some(IssuedSyncChallenge::new(
                        challenge,
                        block_notification.cumulative_proof_of_work,
                        self.now(),
                    ));

                    debug!("sending challenge ...");
                    peer.send(PeerMessage::SyncChallenge(challenge)).await?;

                    // Update the display sync state to reflect the new number.
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                    if let SyncStatus::Challenges(number) = global_state_mut.net.sync_status {
                        global_state_mut.net.sync_status =
                            SyncStatus::Challenges(number.saturating_add(1));
                    } else {
                        global_state_mut.net.sync_status = SyncStatus::Challenges(1);
                    }
                    drop(global_state_mut);

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // If block is new, request it.
                peer_state_info.highest_shared_block_height = block_notification.height;
                let block_is_new = tip_header.cumulative_proof_of_work
                    < block_notification.cumulative_proof_of_work;

                debug!("block_is_new: {}", block_is_new);

                if block_is_new
                    && peer_state_info.fork_reconciliation_blocks.is_empty()
                    && sync_anchor_height.is_none()
                    && !claimed_height_and_pow_exceed_sync_mode_threshold
                {
                    debug!(
                        "sending BlockRequestByHeight to peer for block with height {}",
                        block_notification.height
                    );
                    peer.send(PeerMessage::BlockRequestByHeight(block_notification.height))
                        .await?;

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // If block is not new, maybe we are properly synced?
                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                if tip_header.height == block_notification.height
                    && SyncStatus::Unknown == global_state_mut.net.sync_status
                {
                    global_state_mut.net.sync_status = SyncStatus::Synced;
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::SyncChallenge(sync_challenge) => {
                let response = {
                    log_slow_scope!(fn_name!() + "::PeerMessage::SyncChallenge");

                    info!("Got sync challenge from {}", self.peer_id);

                    // Sync challenges are *always* punished to prevent a
                    // malicious peer from spamming these, as they are expensive
                    // to respond to.
                    self.punish(NegativePeerSanction::ReceivedSyncChallenge)
                        .await?;

                    let response = self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .response_to_sync_challenge(sync_challenge)
                        .await;

                    match response {
                        Ok(resp) => resp,
                        Err(e) => {
                            warn!("could not generate sync challenge response:\n{e}");
                            self.punish(NegativePeerSanction::InvalidSyncChallenge)
                                .await?;
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }
                    }
                };

                debug!("Responding to sync challenge from {} ...", self.peer_id);
                peer.send(PeerMessage::SyncChallengeResponse(Box::new(response)))
                    .await?;
                info!("Responded to sync challenge from {}", self.peer_id);

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::SyncChallengeResponse(challenge_response) => {
                const SYNC_RESPONSE_TIMEOUT: Timestamp = Timestamp::seconds(200);

                log_slow_scope!(fn_name!() + "::PeerMessage::SyncChallengeResponse");
                info!("Got sync challenge response from {}", self.peer_id);

                // The purpose of the sync challenge and sync challenge response
                // is to avoid going into sync mode based on a malicious target
                // fork. Instead of verifying that the claimed proof-of-work
                // number is correct (which would require sending and verifying,
                // at least, all blocks between luca (whatever that is) and the
                // claimed tip), we use a heuristic that requires less
                // communication and less verification work. The downside of
                // using a heuristic here is a nonzero false positive and false
                // negative rate. Note that the false negative event
                // (maliciously sending someone into sync mode based on a bogus
                // fork) still requires a significant amount of work from the
                // attacker, *in addition* to being lucky. Also, down the line
                // succinctness (and more specifically, recursive block
                // validation) obviates this entire subprotocol.

                // Did we issue a challenge?
                let Some(issued_challenge) = peer_state_info.sync_challenge else {
                    warn!("Sync challenge response was not prompted.");
                    self.punish(NegativePeerSanction::UnexpectedSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                };

                // Decrement the display counter.
                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                let sync_anchor = global_state_mut.net.sync_anchor.clone();
                if let SyncStatus::Challenges(number) = global_state_mut.net.sync_status {
                    global_state_mut.net.sync_status =
                        SyncStatus::Challenges(number.saturating_sub(1));
                }
                drop(global_state_mut);

                // Reset the challenge, regardless of the response's success.
                peer_state_info.sync_challenge = None;

                // Does response match issued challenge?
                let network = self.global_state_lock.cli().network;
                if !challenge_response.matches(network, issued_challenge) {
                    self.punish(NegativePeerSanction::InvalidSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                let Ok(challenge_response_tip_hash) =
                    Block::try_from(challenge_response.tip.clone()).map(|block| block.hash())
                else {
                    self.punish(NegativePeerSanction::InvalidSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                };

                // Does response verify?
                let claimed_tip_height = challenge_response.tip.header.height;
                let now = self.now();
                if !challenge_response.is_valid(now, network).await {
                    self.punish(NegativePeerSanction::InvalidSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // If we are already syncing, then most likely another peer
                // activated the sync loop. That's great, now we can sync from
                // multiple peers simultaneously! At this point we know that we
                // are not at risk of being tricked into entering sync mode
                // maliciously. So we can proceed to inform the sync loop of the
                // extra available peer. (Otherwise we need to do more
                // scrutiny.)
                if sync_anchor.is_some() {
                    self.to_main_tx
                        .send(PeerTaskToMain::NewPeer(self.peer_id))
                        .await?;
                    info!("Informing sync loop of new available peer.");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Does cumulative proof-of-work evolve reasonably?
                let own_tip_header = *self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .tip()
                    .header();
                if !challenge_response.check_pow(network, own_tip_header.height) {
                    self.punish(NegativePeerSanction::FishyPowEvolutionChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Is there some specific (*i.e.*, not aggregate) proof of work?
                if network.is_main()
                    && !challenge_response.check_difficulty(own_tip_header.difficulty)
                {
                    self.punish(NegativePeerSanction::FishyDifficultiesChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Did it come in time?
                let time_delta = now - issued_challenge.issued_at;
                if time_delta > SYNC_RESPONSE_TIMEOUT {
                    warn!(
                        "Response from {} to sync challenge came in {} ms but timeout period is {}.",
                        self.peer_id,
                        time_delta.to_millis(),
                        SYNC_RESPONSE_TIMEOUT.to_millis()
                    );
                    self.punish(NegativePeerSanction::TimedOutSyncChallengeResponse)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                info!("Successful sync challenge response; relaying peer tip info to main loop.");
                peer_state_info.successful_sync_challenge_response_time = Some(now);

                let mut sync_mmra_anchor = challenge_response.tip.body.block_mmr_accumulator;
                sync_mmra_anchor.append(issued_challenge.challenge.tip_digest);

                // Inform main loop
                self.to_main_tx
                    .send(PeerTaskToMain::AddPeerMaxBlockHeight {
                        peer_id: self.peer_id,
                        peer_address: self.peer_address.clone(),
                        claimed_height: claimed_tip_height,
                        claimed_cumulative_pow: issued_challenge.accumulated_pow,
                        claimed_block_mmra: sync_mmra_anchor,
                        claimed_block_digest: challenge_response_tip_hash,
                    })
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockRequestByHash(block_digest) => {
                let block = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .get_block(block_digest)
                    .await?;

                match block {
                    None => {
                        if self
                            .global_state_lock
                            .lock_guard()
                            .await
                            .net
                            .sync_anchor
                            .is_none()
                        {
                            self.punish(NegativePeerSanction::RequestForUnknownBlock)
                                .await?;
                        }
                        // TODO: Consider punishing here
                        warn!("Peer requested unknown block with hash {:x}", block_digest);
                        Ok(KEEP_CONNECTION_ALIVE)
                    }
                    Some(b) => {
                        if b.header().height.is_genesis() {
                            self.punish(NegativePeerSanction::RequestForGenesisBlock)
                                .await?;
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }

                        peer.send(PeerMessage::Block(Box::new(b.try_into().unwrap())))
                            .await?;
                        Ok(KEEP_CONNECTION_ALIVE)
                    }
                }
            }
            PeerMessage::BlockRequestByHeight(block_height) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockRequestByHeight");

                debug!("Got BlockRequestByHeight of height {}", block_height);

                if block_height.is_genesis() {
                    self.punish(NegativePeerSanction::RequestForGenesisBlock)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // If a block of that height lives in archival state, send that.
                let canonical_block_digest = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .archival_block_mmr
                    .ammr()
                    .try_get_leaf(block_height.into())
                    .await;
                if let Some(block_digest) = canonical_block_digest {
                    let block = self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .archival_state()
                        .get_block(block_digest)
                        .await?
                        .expect("block should live in archival state because fetching the block digest from height worked");

                    debug!("Sending block");
                    let transfer_block = TransferBlock::try_from(block)
                        .expect("block fetched from archival state should be valid");
                    peer.send(PeerMessage::Block(Box::new(transfer_block)))
                        .await?;
                    debug!("Sent block");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // If we are not syncing, and this block height is unknown, then
                //  a) the peer is confused; or
                //  b) the peer is malicious; or
                //  c) the peer is syncing to a block height higher than our
                //     own. In this last case, the peer will incur punishments
                //     from us until they are synced. However, until they are
                //     synced there is no way for us to determine whether they
                //     are honest or malicious, so until then we treat the
                //     costly response (requiring a disk read) as expensive (in
                //     terms of standing).
                let sync_mode_active = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .sync_anchor
                    .is_some();
                if !sync_mode_active {
                    let own_tip_height = self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .tip()
                        .header()
                        .height;
                    warn!("Got block request by height ({block_height}) for unknown block. Own tip height is {own_tip_height}.");
                    self.punish(NegativePeerSanction::BlockRequestUnknownHeight)
                        .await?;

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // If we are syncing, the requested block might be managed by
                // the sync loop. So ask it. The various handlers downstream
                // this message will eventually send the peer a response.
                let _ = self
                    .to_main_tx
                    .send(PeerTaskToMain::PeerWantsSyncBlock(
                        self.peer_id,
                        block_height,
                    ))
                    .await;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Block(t_block) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::Block");

                debug!(
                    "Got new block from peer {}, height {}, mined {}",
                    self.peer_id,
                    t_block.header.height,
                    t_block.header.timestamp.standard_format()
                );

                let block = match Block::try_from(*t_block) {
                    Ok(block) => Box::new(block),
                    Err(e) => {
                        warn!("Peer sent invalid block: {e:?}");
                        self.punish(NegativePeerSanction::InvalidTransferBlock)
                            .await?;

                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                // If sync mode is active, incoming blocks are destined for the
                // sync loop.
                let network = self.global_state_lock.cli().network;
                let mut state_lock = self.global_state_lock.lock_guard_mut().await;
                if let Some(sync_anchor) = &mut state_lock.net.sync_anchor {
                    let height = block.header().height;
                    let digest = block.hash();

                    // Ensure that at least the block proof is valid, before
                    // storing. Otherwise this path is open to a DOS attack.
                    // Full validation in relation to the predecessor happens in
                    // the sync loop.
                    let is_valid = block.validate_block_proof(network).await.is_ok();
                    if !is_valid {
                        drop(state_lock);
                        self.punish(NegativePeerSanction::InvalidBlock((height, digest)))
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }

                    let is_successor = block.header().prev_block_digest == sync_anchor.champion.1;
                    let is_new_champion = sync_anchor.incoming_block_is_new_champion(height);
                    if is_successor && is_new_champion {
                        // Inform main loop about a new tip-successor.
                        self.to_main_tx
                            .send(PeerTaskToMain::NewSyncTarget(block))
                            .await?;

                        // Keep sync anchor up to date.
                        sync_anchor.catch_up(height, digest);
                    } else if is_new_champion {
                        // The incoming block is the new champion but is not the
                        // successor of the current tip. This happens when
                        //  a) the peer sends new blocks out of order, or one of
                        //     the intermediate blocks was dropped in transit;
                        //     or
                        //  b) the peer reorg'ed.
                        // In either case, we can deal with the problem once
                        // sync mode is done. So ignore for now.
                        tracing::warn!(
                            "Block {} / {:x} from peer {} is new champion but not successor to tip; ignoring.",
                            height,
                            digest,
                            self.peer_id
                        );
                    } else if is_successor {
                        // Cannot happen.
                        tracing::error!(
                            "Block {} / {:x} from peer {} is successor to tip but not new champion; ignoring. Cannot happen.",
                            height,
                            digest,
                            self.peer_id
                        );
                    } else {
                        // Inform main loop about a new middle block.
                        self.to_main_tx
                            .send(PeerTaskToMain::NewSyncBlock(block, self.peer_id))
                            .await?;
                    }
                    return Ok(KEEP_CONNECTION_ALIVE);
                }
                drop(state_lock);

                // Activate the shallow fork reconciliation mechanism if
                // necessary, otherwise immediately proceed to processing the
                // block.
                if let Some(new_block_height) =
                    self.try_ensure_path(block, peer, peer_state_info).await?
                {
                    // Update the tracker variable tracking the height of the
                    // highest block shared with us so far by this peer.
                    peer_state_info.highest_shared_block_height = new_block_height;
                }

                // Reward happens as part of `try_ensure_path`

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockRequestBatch(BlockRequestBatch {
                known_blocks,
                max_response_len,
                anchor,
            }) => {
                debug!(
                    "Received BlockRequestBatch from peer {}, max_response_len: {max_response_len}",
                    self.peer_id
                );

                if known_blocks.len() > MAX_NUM_DIGESTS_IN_BATCH_REQUEST {
                    self.punish(NegativePeerSanction::BatchBlocksRequestTooManyDigests)
                        .await?;

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // The last block in the list of the peer's known block is the
                // earliest block, block with lowest height, the peer has
                // requested. If it does not belong to canonical chain, none of
                // the later will. So we can do an early abort in that case.
                let least_preferred = match known_blocks.last() {
                    Some(least_preferred) => *least_preferred,
                    None => {
                        self.punish(NegativePeerSanction::BatchBlocksRequestEmpty)
                            .await?;

                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                let state = self.global_state_lock.lock_guard().await;
                let block_mmr_num_leafs = state.chain.tip().header().height.next().into();
                let luca_is_known = state
                    .chain
                    .archival_state()
                    .block_belongs_to_canonical_chain(least_preferred)
                    .await;
                if !luca_is_known || anchor.num_leafs() > block_mmr_num_leafs {
                    drop(state);
                    self.punish(NegativePeerSanction::BatchBlocksUnknownRequest)
                        .await?;
                    peer.send(PeerMessage::UnableToSatisfyBatchRequest).await?;

                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Happy case: At least *one* of the blocks referenced by peer
                // is known to us.
                let first_block_in_response = {
                    let mut first_block_in_response: Option<BlockHeight> = None;
                    for block_digest in known_blocks {
                        if state
                            .chain
                            .archival_state()
                            .block_belongs_to_canonical_chain(block_digest)
                            .await
                        {
                            let height = state
                                .chain
                                .archival_state()
                                .get_block_header(block_digest)
                                .await
                                .unwrap()
                                .height;
                            first_block_in_response = Some(height);
                            debug!(
                                "Found block in canonical chain for batch response: {}",
                                block_digest
                            );
                            break;
                        }
                    }

                    first_block_in_response
                        .expect("existence of LUCA should have been established already.")
                };

                debug!(
                    "Peer's most preferred block has height {first_block_in_response}.\
                 Now building response from that height."
                );

                // Get the relevant blocks, at most batch-size many, descending from the
                // peer's (alleged) most canonical block. Don't exceed `max_response_len`
                // or `STANDARD_BLOCK_BATCH_SIZE` number of blocks in response.
                let max_response_len = cmp::min(
                    max_response_len,
                    self.global_state_lock.cli().sync_mode_threshold,
                );
                let max_response_len = cmp::max(max_response_len, MINIMUM_BLOCK_BATCH_SIZE);
                let max_response_len = cmp::min(max_response_len, STANDARD_BLOCK_BATCH_SIZE);

                let mut digests_of_returned_blocks = Vec::with_capacity(max_response_len);
                let response_start_height: u64 = first_block_in_response.into();
                let mut i: u64 = 1;
                while digests_of_returned_blocks.len() < max_response_len {
                    let block_height = response_start_height + i;
                    match state
                        .chain
                        .archival_state()
                        .archival_block_mmr
                        .ammr()
                        .try_get_leaf(block_height)
                        .await
                    {
                        Some(digest) => {
                            digests_of_returned_blocks.push(digest);
                        }
                        None => break,
                    }
                    i += 1;
                }

                let mut returned_blocks: Vec<Block> =
                    Vec::with_capacity(digests_of_returned_blocks.len());
                for block_digest in digests_of_returned_blocks {
                    let block = state
                        .chain
                        .archival_state()
                        .get_block(block_digest)
                        .await?
                        .unwrap();
                    returned_blocks.push(block);
                }

                let response = Self::batch_response(&state, returned_blocks, &anchor).await;

                // issue 457. do not hold lock across a peer.send(), nor self.punish()
                drop(state);

                let Some(response) = response else {
                    warn!("Unable to satisfy batch-block request");
                    self.punish(NegativePeerSanction::BatchBlocksUnknownRequest)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                };

                debug!("Returning {} blocks in batch response", response.len());

                let response = PeerMessage::BlockResponseBatch(response);
                peer.send(response).await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockResponseBatch(authenticated_blocks) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::BlockResponseBatch");

                debug!(
                    "handling block response batch with {} blocks",
                    authenticated_blocks.len()
                );

                // (Alan:) why is there even a minimum?
                if authenticated_blocks.len() < MINIMUM_BLOCK_BATCH_SIZE {
                    warn!("Got smaller batch response than allowed");
                    self.punish(NegativePeerSanction::TooShortBlockBatch)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Verify that we are in fact in syncing mode
                // TODO: Separate peer messages into those allowed under syncing
                // and those that are not
                let Some(sync_anchor) = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .sync_anchor
                    .clone()
                else {
                    warn!("Received a batch of blocks without being in syncing mode");
                    self.punish(NegativePeerSanction::ReceivedBatchBlocksOutsideOfSync)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                };

                // Verify that the response matches the current state
                // We get the latest block from the DB here since this message is
                // only valid for archival nodes.
                let (first_block, _) = &authenticated_blocks[0];
                let first_blocks_parent_digest: Digest = first_block.header.prev_block_digest;
                let most_canonical_own_block_match: Option<Block> = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .get_block(first_blocks_parent_digest)
                    .await
                    .expect("Block lookup must succeed");
                let most_canonical_own_block_match: Block = match most_canonical_own_block_match {
                    Some(block) => block,
                    None => {
                        warn!("Got batch response with invalid start block");
                        self.punish(NegativePeerSanction::BatchBlocksInvalidStartHeight)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                };

                // Convert all blocks to Block objects
                debug!(
                    "Found own block of height {} to match received batch",
                    most_canonical_own_block_match.kernel.header.height
                );
                let mut received_blocks = vec![];
                for (t_block, membership_proof) in authenticated_blocks {
                    let Ok(block) = Block::try_from(t_block) else {
                        warn!("Received invalid transfer block from peer");
                        self.punish(NegativePeerSanction::InvalidTransferBlock)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    };

                    if !membership_proof.verify(
                        block.header().height.into(),
                        block.hash(),
                        &sync_anchor.block_mmr.peaks(),
                        sync_anchor.block_mmr.num_leafs(),
                    ) {
                        warn!("Authentication of received block fails relative to anchor");
                        self.punish(NegativePeerSanction::InvalidBlockMmrAuthentication)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }

                    received_blocks.push(block);
                }

                // Get the latest block that we know of and handle all received blocks
                self.handle_blocks(received_blocks, most_canonical_own_block_match)
                    .await?;

                // Reward happens as part of `handle_blocks`.

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::UnableToSatisfyBatchRequest => {
                log_slow_scope!(fn_name!() + "::PeerMessage::UnableToSatisfyBatchRequest");
                warn!(
                    "Peer {} reports inability to satisfy batch request.",
                    self.peer_id
                );

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Handshake { .. } => {
                log_slow_scope!(fn_name!() + "::PeerMessage::Handshake");

                // The handshake should have been sent during connection
                // initialization. Here it is out of order at best, malicious at
                // worst.
                self.punish(NegativePeerSanction::InvalidMessage).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::ConnectionStatus(_) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::ConnectionStatus");

                // The connection status should have been sent during connection
                // initialization. Here it is out of order at best, malicious at
                // worst.

                self.punish(NegativePeerSanction::InvalidMessage).await?;
                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::Transaction(transaction) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::Transaction");

                // Early check for oversized announcements to prevent DoS
                for announcement in &transaction.kernel.announcements {
                    if announcement.message.len() > MAX_ANNOUNCEMENT_MESSAGE_SIZE {
                        warn!(
                            "Received transaction with oversized announcement: {} BFEs (max: {})",
                            announcement.message.len(),
                            MAX_ANNOUNCEMENT_MESSAGE_SIZE
                        );
                        self.punish(NegativePeerSanction::OversizedAnnouncement)
                            .await?;
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                }

                let num_inputs: u64 = transaction.kernel.inputs.len().try_into().unwrap();
                debug!(
                    "`peer_loop` received following transaction from peer. {num_inputs} inputs,\
                     {} outputs. Synced to mutator set hash: {}",
                    transaction.kernel.outputs.len(),
                    transaction.kernel.mutator_set_hash
                );

                if !self.global_state_lock.cli().relay_transaction(
                    num_inputs,
                    transaction.kernel.fee,
                    transaction.proof.proof_quality(),
                ) {
                    warn!("Received transaction not meeting relay criteria");
                    self.punish(NegativePeerSanction::UnrelayableTransaction)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                let transaction: Transaction = (*transaction).into();

                let (tip, mutator_set_accumulator_after, current_block_height) = {
                    let state = self.global_state_lock.lock_guard().await;

                    (
                        state.chain.tip_hash(),
                        state.chain.tip_mutator_set_after(),
                        state.chain.tip_height(),
                    )
                };

                // 1. If transaction is invalid, punish.
                let network = self.global_state_lock.cli().network;
                let consensus_rule_set =
                    ConsensusRuleSet::infer_from(network, current_block_height);
                if !transaction.is_valid(network, consensus_rule_set).await {
                    warn!("Received invalid tx");
                    self.punish(NegativePeerSanction::InvalidTransaction)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 2. If transaction has coinbase, punish.
                // Transactions received from peers have not been mined yet.
                // Only the miner is allowed to produce transactions with non-empty coinbase fields.
                if transaction.kernel.coinbase.is_some() {
                    warn!("Received non-mined transaction with coinbase.");
                    self.punish(NegativePeerSanction::NonMinedTransactionHasCoinbase)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 3. If negative fee, punish.
                if transaction.kernel.fee.is_negative() {
                    warn!("Received negative-fee transaction.");
                    self.punish(NegativePeerSanction::TransactionWithNegativeFee)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 4. Check if transaction is already known.
                if !self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .mempool
                    .accept_transaction(
                        transaction.kernel.txid(),
                        transaction.proof.proof_quality(),
                        transaction.kernel.mutator_set_hash,
                    )
                {
                    warn!("Received transaction that was already known");

                    // We received a transaction that we *probably* haven't requested.
                    // Consider punishing here, if this is abused.
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 5. if transaction is not confirmable, punish.
                if !transaction.is_confirmable_relative_to(&mutator_set_accumulator_after) {
                    warn!(
                        "Received unconfirmable transaction with TXID {}. Unconfirmable because:",
                        transaction.kernel.txid()
                    );
                    // get fine-grained error code for informative logging
                    let confirmability_error_code = transaction
                        .kernel
                        .is_confirmable_relative_to(&mutator_set_accumulator_after);
                    match confirmability_error_code {
                        Ok(_) => unreachable!(),
                        Err(TransactionConfirmabilityError::InvalidRemovalRecord(index)) => {
                            warn!("invalid removal record (at index {index})");
                            let invalid_removal_record = transaction.kernel.inputs[index].clone();
                            let removal_record_error_code = invalid_removal_record
                                .validate_inner(&mutator_set_accumulator_after);
                            debug!(
                                "Absolute index set of removal record {index}: {:?}",
                                invalid_removal_record.absolute_indices
                            );
                            match removal_record_error_code {
                                Ok(_) => unreachable!(),
                                Err(RemovalRecordValidityError::AbsentAuthenticatedChunk) => {
                                    debug!("invalid because membership proof is missing");
                                }
                                Err(RemovalRecordValidityError::InvalidSwbfiMmrMp {
                                    chunk_index,
                                }) => {
                                    debug!("invalid because membership proof for chunk index {chunk_index} is invalid");
                                }
                            };
                            self.punish(NegativePeerSanction::UnconfirmableTransaction)
                                .await?;
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }
                        Err(TransactionConfirmabilityError::DuplicateInputs) => {
                            warn!("duplicate inputs");
                            self.punish(NegativePeerSanction::DoubleSpendingTransaction)
                                .await?;
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }
                        Err(TransactionConfirmabilityError::AlreadySpentInput(index)) => {
                            warn!("already spent input (at index {index})");
                            self.punish(NegativePeerSanction::DoubleSpendingTransaction)
                                .await?;
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }
                        Err(TransactionConfirmabilityError::RemovalRecordUnpackFailure) => {
                            warn!("Failed to unpack removal records");
                            self.punish(NegativePeerSanction::InvalidTransaction)
                                .await?;
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }
                    };
                }

                // If transaction cannot be applied to mutator set, punish.
                // I don't think this can happen when above checks pass but we include
                // the check to ensure that transaction can be applied.
                let ms_update = MutatorSetUpdate::new(
                    transaction.kernel.inputs.clone(),
                    transaction.kernel.outputs.clone(),
                );
                let can_apply = ms_update
                    .apply_to_accumulator(&mut mutator_set_accumulator_after.clone())
                    .is_ok();
                if !can_apply {
                    warn!("Cannot apply transaction to current mutator set.");
                    warn!("Transaction ID: {}", transaction.kernel.txid());
                    self.punish(NegativePeerSanction::CannotApplyTransactionToMutatorSet)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                let tx_timestamp = transaction.kernel.timestamp;

                // 6. Ignore if transaction is too old
                let now = self.now();
                if tx_timestamp < now - Timestamp::seconds(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS) {
                    // TODO: Consider punishing here
                    warn!("Received too old tx");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // 7. Ignore if transaction is too far into the future
                if tx_timestamp >= now + FUTUREDATING_LIMIT {
                    // TODO: Consider punishing here
                    warn!("Received tx too far into the future. Got timestamp: {tx_timestamp:?}");
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Otherwise, relay to main
                let pt2m_transaction = PeerTaskToMainTransaction {
                    transaction,
                    confirmable_for_block: tip,
                };
                self.to_main_tx
                    .send(PeerTaskToMain::Transaction(Box::new(pt2m_transaction)))
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::TransactionNotification(tx_notification) => {
                // addresses #457
                // new scope for state read-lock to avoid holding across peer.send()
                {
                    log_slow_scope!(fn_name!() + "::PeerMessage::TransactionNotification");

                    // 0. Check that transaction meets relay criteria
                    if !self.global_state_lock.cli().relay_transaction(
                        tx_notification.num_inputs,
                        tx_notification.fee,
                        tx_notification.proof_quality,
                    ) {
                        debug!("transaction does not meet relay criteria");
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }

                    // 1. Ignore if we already know this transaction, and
                    // the proof quality is not higher than what we already know.
                    let state = self.global_state_lock.lock_guard().await;
                    let accept_tx = state.mempool.accept_transaction(
                        tx_notification.txid,
                        tx_notification.proof_quality,
                        tx_notification.mutator_set_hash,
                    );
                    if !accept_tx {
                        debug!("transaction with same or higher proof quality was already known");
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }

                    // Only accept transactions that do not require executing
                    // `update`.
                    if state.chain.tip_mutator_set_after().hash()
                        != tx_notification.mutator_set_hash
                    {
                        debug!("transaction refers to non-canonical mutator set state");
                        return Ok(KEEP_CONNECTION_ALIVE);
                    }
                }

                // 2. Request the actual `Transaction` from peer
                debug!("requesting transaction from peer");
                peer.send(PeerMessage::TransactionRequest(tx_notification.txid))
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::TransactionRequest(transaction_identifier) => {
                let state = self.global_state_lock.lock_guard().await;
                let Some(transaction) = state.mempool.get(transaction_identifier) else {
                    return Ok(KEEP_CONNECTION_ALIVE);
                };

                let Ok(transfer_transaction) = transaction.try_into() else {
                    warn!("Peer requested transaction that cannot be converted to transfer object");
                    return Ok(KEEP_CONNECTION_ALIVE);
                };

                // Drop state immediately to prevent holding over a response.
                drop(state);

                peer.send(PeerMessage::Transaction(Box::new(transfer_transaction)))
                    .await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockProposalNotification(block_proposal_notification) => {
                let verdict = self
                    .global_state_lock
                    .cli()
                    .accept_block_proposal_from(&self.peer_address);

                // Avoid acquiring lock if ip validation failed
                let verdict = verdict.map(async |_| {
                    self.global_state_lock
                        .lock_guard()
                        .await
                        .favor_incoming_block_proposal_legacy(
                            block_proposal_notification.height,
                            block_proposal_notification.guesser_fee,
                        )
                });

                match verdict {
                    Ok(_) => {
                        peer.send(PeerMessage::BlockProposalRequest(
                            BlockProposalRequest::new(block_proposal_notification.body_mast_hash),
                        ))
                        .await?
                    }
                    Err(reject_reason) => {
                        debug!(
                        "Rejecting notification of block proposal with guesser fee {} from peer \
                        {}. Reason:\n{reject_reason}",
                        block_proposal_notification.guesser_fee.display_n_decimals(5),
                        self.peer_id
                    )
                    }
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockProposalRequest(block_proposal_request) => {
                let matching_proposal = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .mining_state
                    .block_proposal
                    .filter(|x| x.body().mast_hash() == block_proposal_request.body_mast_hash)
                    .map(|x| x.to_owned());
                if let Some(proposal) = matching_proposal {
                    peer.send(PeerMessage::BlockProposal(Box::new(proposal)))
                        .await?;
                } else {
                    self.punish(NegativePeerSanction::BlockProposalNotFound)
                        .await?;
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::BlockProposal(new_proposal) => {
                debug!("Got block proposal from peer.");

                let verdict = self
                    .global_state_lock
                    .cli()
                    .accept_block_proposal_from(&self.peer_address);

                // Avoid taking any locks if we don't accept block proposals
                // from this IP
                if verdict.is_err() {
                    self.punish(NegativePeerSanction::BlockProposalFromBlockedPeer)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Is the proposal valid?
                // Lock needs to be held here because race conditions: otherwise
                // the block proposal that was validated might not match with
                // the one whose favorability is being computed.
                let state = self.global_state_lock.lock_guard().await;
                let tip = state.chain.tip();
                let proposal_is_valid = new_proposal
                    .is_valid(tip, self.now(), self.global_state_lock.cli().network)
                    .await;
                if !proposal_is_valid {
                    drop(state);
                    self.punish(NegativePeerSanction::InvalidBlockProposal)
                        .await?;
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                // Is block proposal favorable?
                let is_favorable = state.favor_incoming_block_proposal(
                    new_proposal.header().prev_block_digest,
                    new_proposal
                        .body()
                        .total_guesser_reward()
                        .expect("Block was validated"),
                );
                drop(state);

                if let Err(rejection_reason) = is_favorable {
                    match rejection_reason {
                        // no need to punish and log if the fees are equal.  we just ignore the incoming proposal.
                        BlockProposalRejectError::InsufficientFee { current, received }
                            if Some(received) == current =>
                        {
                            debug!("ignoring new block proposal because the fee is equal to the present one");
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }
                        _ => {
                            warn!("Rejecting new block proposal:\n{rejection_reason}");
                            self.punish(NegativePeerSanction::NonFavorableBlockProposal)
                                .await?;
                            return Ok(KEEP_CONNECTION_ALIVE);
                        }
                    }
                };

                self.send_to_main(PeerTaskToMain::BlockProposal(new_proposal), line!())
                    .await?;

                // Valuable, new, hard-to-produce information. Reward peer.
                self.reward(PositivePeerSanction::NewBlockProposal).await?;

                Ok(KEEP_CONNECTION_ALIVE)
            }
            PeerMessage::SyncCoverage(synchronization_bit_mask) => {
                log_slow_scope!(fn_name!() + "::PeerMessage::SyncCoverage");

                // Test if sync mode is active.
                if self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .sync_anchor
                    .is_some()
                {
                    // If so, pass bit mask on to main loop for relaying to sync
                    // loop.
                    self.to_main_tx
                        .send(PeerTaskToMain::SyncCoverage(
                            synchronization_bit_mask,
                            self.peer_id,
                        ))
                        .await?;
                } else {
                    warn!(
                        "Got synchronization bit mask (coverage) from peer, but not in sync mode."
                    );
                }

                Ok(KEEP_CONNECTION_ALIVE)
            }
        }
    }

    /// send msg to main via mpsc channel `to_main_tx` and logs if slow.
    ///
    /// the channel could potentially fill up in which case the send() will
    /// block until there is capacity.  we wrap the send() so we can log if
    /// that ever happens to the extent it passes slow-scope threshold.
    async fn send_to_main(
        &self,
        msg: PeerTaskToMain,
        line: u32,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<PeerTaskToMain>> {
        // we measure across the send() in case the channel ever fills up.
        log_slow_scope!(fn_name!() + &format!("peer_loop.rs:{}", line));

        self.to_main_tx.send(msg).await
    }

    /// Handle message from main task. The boolean return value indicates if
    /// the connection should be closed.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write via Self::punish()
    async fn handle_main_task_message<S>(
        &mut self,
        msg: MainToPeerTask,
        peer: &mut S,
        peer_state_info: &mut MutablePeerState,
    ) -> Result<bool>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        debug!("Handling {} message from main in peer loop", msg.get_type());
        match msg {
            MainToPeerTask::Block(block) => {
                // We don't currently differentiate whether a new block came from a peer, or from our
                // own miner. It's always shared through this logic.
                let new_block_height = block.kernel.header.height;
                if new_block_height > peer_state_info.highest_shared_block_height {
                    debug!("Sending PeerMessage::BlockNotification");
                    peer_state_info.highest_shared_block_height = new_block_height;
                    peer.send(PeerMessage::BlockNotification(block.as_ref().into()))
                        .await?;
                    debug!("Sent PeerMessage::BlockNotification");
                }
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::RequestBlockByHeight {
                target_peer,
                height,
            } => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::RequestBlockByHeight");
                // Only ask one of the peers about the batch of blocks
                if target_peer != self.peer_id {
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                if height.is_genesis() {
                    error!("Requested the genesis block from another peer. This should never happen. Programmer error.");
                    std::process::exit(255);
                }

                peer.send(PeerMessage::BlockRequestByHeight(height)).await?;

                debug!("sent block-request-by-height ({height}) to peer {target_peer}");

                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::PeerSynchronizationTimeout(peer_id) => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::PeerSynchronizationTimeout");

                if self.peer_id != peer_id {
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                self.punish(NegativePeerSanction::SynchronizationTimeout)
                    .await?;

                // If this peer failed the last synchronization attempt, we only
                // sanction, we don't disconnect.
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::Disconnect(peer_id) => {
                log_slow_scope!(fn_name!() + "::MainToPeerTask::Disconnect");

                // Only disconnect from the peer the main task requested a disconnect for.
                if peer_id != self.peer_id {
                    return Ok(KEEP_CONNECTION_ALIVE);
                }

                peer.send(PeerMessage::Bye).await?;

                self.register_peer_disconnection().await;

                Ok(DISCONNECT_CONNECTION)
            }
            MainToPeerTask::DisconnectAll() => {
                peer.send(PeerMessage::Bye).await?;

                self.register_peer_disconnection().await;

                Ok(DISCONNECT_CONNECTION)
            }
            MainToPeerTask::TransactionNotification(transaction_notification) => {
                debug!("Sending PeerMessage::TransactionNotification");
                peer.send(PeerMessage::TransactionNotification(
                    transaction_notification,
                ))
                .await?;
                debug!("Sent PeerMessage::TransactionNotification");
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::BlockProposalNotification(block_proposal_notification) => {
                debug!("Sending PeerMessage::BlockProposalNotification");
                peer.send(PeerMessage::BlockProposalNotification(
                    block_proposal_notification,
                ))
                .await?;
                debug!("Sent PeerMessage::BlockProposalNotification");
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::RequestBlockNotification => {
                debug!("Sending PeerMessage::BlockNotificationRequest");
                peer.send(PeerMessage::BlockNotificationRequest).await?;
                debug!("Sent PeerMessage::BlockNotificationRequest");
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::SyncCoverage {
                coverage,
                peer_handle,
            } => {
                if self.peer_id == peer_handle {
                    peer.send(PeerMessage::SyncCoverage(coverage)).await?;
                }
                Ok(KEEP_CONNECTION_ALIVE)
            }
            MainToPeerTask::SyncBlock { block, peer_handle } => {
                if self.peer_id == peer_handle {
                    let transfer_block = TransferBlock::try_from(*block)
                        .expect("block fetched from sync loop should be castable into transfer block because that's where it came from");
                    peer.send(PeerMessage::Block(Box::new(transfer_block)))
                        .await?;
                }
                Ok(KEEP_CONNECTION_ALIVE)
            }
        }
    }

    /// Loop for the peer tasks. Awaits either a message from the peer over TCP,
    /// or a message from main over the main-to-peer-tasks broadcast channel.
    async fn run<S>(
        &mut self,
        mut peer: S,
        mut from_main_rx: broadcast::Receiver<MainToPeerTask>,
        peer_state_info: &mut MutablePeerState,
    ) -> Result<()>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        loop {
            select! {
                // Handle peer messages
                peer_message = peer.try_next() => {
                    let peer_address = self.peer_id;
                    let peer_message = match peer_message {
                        Ok(message) => message,
                        Err(err) => {
                            // Don't disconnect if message type is unknown, as
                            // this allows the adding of new message types in
                            // the future. Consider only keeping connection open
                            // if this is a deserialization error, and close
                            // otherwise.
                            let msg = format!("Error when receiving from peer: {peer_address}");
                            warn!("{msg}. Error: {err}");
                            self.punish(NegativePeerSanction::InvalidMessage).await?;
                            continue;
                        }
                    };
                    let Some(peer_message) = peer_message else {
                        info!("Peer {peer_address} closed connection.");
                        break;
                    };

                    let (syncing, frozen) =
                        self.global_state_lock.lock(|s| (s.net.sync_anchor.is_some(), s.net.freeze)).await;
                    let message_type = peer_message.get_type();
                    if syncing && peer_message.ignore_during_sync() {
                        debug!(
                            "Ignoring {message_type} message when syncing, from {peer_address}",
                        );
                        continue;
                    }
                    if peer_message.ignore_when_not_sync() && !syncing {
                        debug!(
                            "Ignoring {message_type} message when not syncing, from {peer_address}",
                        );
                        continue;
                    }
                    if frozen && peer_message.ignore_on_freeze() {
                        debug!("Ignoring message because state updates have been paused.");
                        continue;
                    }

                    match self
                        .handle_peer_message(peer_message, &mut peer, peer_state_info)
                        .await
                    {
                        Ok(false) => {}
                        Ok(true) => {
                            info!("Closing connection to {peer_address}");
                            break;
                        }
                        Err(err) => {
                            warn!("Closing connection to {peer_address} because of error {err}.");
                            bail!("{err}");
                        }
                    };
                }

                // Handle messages from main task
                main_msg_res = from_main_rx.recv() => {
                    let main_msg = main_msg_res.unwrap_or_else(|err| {
                        let err_msg = format!("Failed to read from main loop: {err}");
                        error!(err_msg);
                        panic!("{err_msg}");
                    });

                    let frozen = self.global_state_lock.lock_guard().await.net.freeze;
                    if frozen && main_msg.ignore_on_freeze() {
                        warn!("Peer loop ignores message from main loop because state updates have been paused");
                        continue;
                    }

                    let close_connection = self
                        .handle_main_task_message(main_msg, &mut peer, peer_state_info)
                        .await
                        .unwrap_or_else(|err| {
                            warn!("handle_main_task_message returned an error: {err}");
                            true
                        });

                    if close_connection {
                        info!(
                            "handle_main_task_message is closing the connection to {}",
                            self.peer_id
                        );
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Function called before entering the peer loop. Reads the potentially stored
    /// peer standing from the database and does other book-keeping before entering
    /// its final resting place: the `peer_loop`. Note that the peer has already been
    /// accepted for a connection for this loop to be entered. So we don't need
    /// to check the standing again.
    ///
    /// This function is shared between the legacy and libp2p network stacks.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write
    pub(crate) async fn run_wrapper<S>(
        &mut self,
        mut peer: S,
        from_main_rx: broadcast::Receiver<MainToPeerTask>,
    ) -> Result<()>
    where
        S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
        <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
        <S as TryStream>::Error: std::error::Error,
    {
        let cli_args = self.global_state_lock.cli().clone();

        let maybe_ip = self.peer_address.iter().find_map(|p| match p {
            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        });
        let standing = if let Some(ip) = maybe_ip {
            self.global_state_lock
                .lock_guard()
                .await
                .net
                .peer_databases
                .peer_standings_by_ip
                .get(ip)
                .await
                .unwrap_or_else(|| PeerStanding::new(cli_args.peer_tolerance))
        } else {
            PeerStanding::new(cli_args.peer_tolerance)
        };

        // Add peer to peer map
        let peer_connection_info =
            PeerConnectionInfo::new(self.peer_address.clone(), self.inbound_connection);
        let new_peer = PeerInfo::new(
            peer_connection_info,
            &self.peer_handshake_data,
            SystemTime::now(),
            cli_args.peer_tolerance,
        )
        .with_standing(standing);

        // Multiple tasks might attempt to set up a connection concurrently. So
        // even though we've checked that this connection is allowed, this check
        // could have been invalidated by another task, for one accepting an
        // incoming connection from a peer we're currently connecting to. So we
        // need to make the a check again while holding a write-lock, since
        // we're modifying `peer_map` here. Holding a read-lock doesn't work
        // since it would have to be dropped before acquiring the write-lock.
        {
            let mut global_state = self.global_state_lock.lock_guard_mut().await;
            let peer_map = &mut global_state.net.peer_map;
            if peer_map
                .values()
                .any(|pi| pi.instance_id() == self.peer_handshake_data.instance_id)
            {
                bail!("Already connected to peer with this instance ID. Aborting connection.");
            }

            if peer_map.len() >= cli_args.max_num_peers {
                bail!("Attempted to connect to more peers than allowed. Aborting connection.");
            }

            if peer_map.contains_key(&self.peer_id) {
                bail!("Already connected to peer with this peer ID. Aborting connection.");
            }

            peer_map.insert(self.peer_id, new_peer);

            // If we are in sync mode, tell the main loop there is a new peer so
            // that it can relay the message to the sync loop.
            if global_state.net.sync_anchor.is_some() {
                debug!("We are syncing, so tell the sync loop about the new peer.");
                self.to_main_tx
                    .send(PeerTaskToMain::NewPeer(self.peer_id))
                    .await?;
            }
        }

        // `MutablePeerState` contains the part of the peer-loop's state that is mutable
        let mut peer_state = MutablePeerState::new(self.peer_handshake_data.tip_header.height);

        // If peer indicates more canonical block, request a block notification to catch up ASAP
        if self.peer_handshake_data.tip_header.cumulative_proof_of_work
            > self
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .tip()
                .kernel
                .header
                .cumulative_proof_of_work
        {
            // Send block notification request to catch up ASAP, in case we're
            // behind the newly-connected peer.
            peer.send(PeerMessage::BlockNotificationRequest).await?;
        }

        // Run the peer loop inside a catch-unwind, so that we can guarantee
        // that the close-callback is run afterwards -- even in the case of
        // panic.
        let panic_result = std::panic::AssertUnwindSafe(async {
            self.run(peer, from_main_rx, &mut peer_state).await
        })
        .catch_unwind()
        .await;

        debug!("Exited peer loop for {}", self.peer_id);

        let peer_loop_result = match panic_result {
            Ok(inner_res) => inner_res,
            Err(e) => {
                error!(
                    "Peer task (incoming) for {} panicked. Invoking close connection callback",
                    self.peer_id
                );
                error!("{e:?}");

                Ok(())
            }
        };

        close_peer_connected_callback(
            self.global_state_lock.clone(),
            self.peer_address.clone(),
            &self.to_main_tx,
        )
        .await;

        debug!("Ending peer loop for {}", self.peer_id);

        // Return any error that `run` returned. Returning and not suppressing errors is a quite nice
        // feature to have for testing purposes.
        peer_loop_result
    }

    /// Register graceful peer disconnection in the global state.
    ///
    /// See also [`NetworkingState::register_peer_disconnection`][1].
    ///
    /// # Locking:
    ///   * acquires `global_state_lock` for write
    ///
    /// [1]: crate::state::networking_state::NetworkingState::register_peer_disconnection
    async fn register_peer_disconnection(&mut self) {
        let peer_id = self.peer_handshake_data.instance_id;
        self.global_state_lock
            .lock_guard_mut()
            .await
            .net
            .register_peer_disconnection(peer_id, SystemTime::now());
    }
}

/// Remove peer from state. This function must be called every time
/// a peer is disconnected. Whether this happens through a panic
/// in the peer task or through a regular disconnect.
///
/// TODO: make this part of handler?
///
/// Locking:
///   * acquires `global_state_lock` for write
pub(crate) async fn close_peer_connected_callback(
    mut global_state_lock: GlobalStateLock,
    peer_address: Multiaddr,
    to_main_tx: &mpsc::Sender<PeerTaskToMain>,
) {
    let cli_arguments = global_state_lock.cli().clone();
    let mut global_state_mut = global_state_lock.lock_guard_mut().await;

    // Find the matching peer id
    let Some(peer_id) = global_state_mut
        .net
        .peer_map
        .iter()
        .find(|(_peer_id, peer_info)| peer_info.address() == peer_address)
        .map(|(peer_id, _)| peer_id)
        .copied()
    else {
        error!("Could not find peer id for {peer_address}");
        return;
    };

    // Store any new peer-standing to database
    let peer_info_writeback = global_state_mut.net.peer_map.remove(&peer_id);
    let new_standing = if let Some(new) = peer_info_writeback {
        new.standing()
    } else {
        error!("Could not find peer standing for {peer_address}");
        let mut standing = PeerStanding::new(cli_arguments.peer_tolerance);
        let sanction = NegativePeerSanction::NoStandingFoundMaybeCrash;

        // Don't return early: _must_ send message to main loop at the end of this
        // function.
        // If the peer has now reached bad standing, the connection to it should be
        // dropped, which is currently happening anyway.
        let _ = standing.sanction(PeerSanction::Negative(sanction));
        standing
    };
    debug!("Fetched peer info standing {new_standing} for peer {peer_address}");

    let maybe_ip = peer_address.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    });
    if let Some(ip) = maybe_ip {
        global_state_mut
            .net
            .write_peer_standing_on_decrease(ip, new_standing)
            .await;
    }

    let sync_mode_is_active = global_state_mut.net.sync_anchor.is_some();
    drop(global_state_mut); // avoid holding across mpsc::Sender::send()
    debug!("Stored peer info standing {new_standing} for peer {peer_address}");

    // If in sync mode, tell sync loop about dropped peer.
    if sync_mode_is_active {
        to_main_tx
            .send(PeerTaskToMain::DroppedPeer(peer_id))
            .await
            .expect("channel to main should exist");
    }
}
