pub mod block_appendix;
pub mod block_body;
pub mod block_header;
pub mod block_height;
pub mod block_kernel;
pub mod block_transaction;
mod block_validation_error;
pub mod difficulty_control;
pub mod guesser_receiver_data;
pub mod mutator_set_update;
pub mod pow;
pub mod validity;

use std::sync::OnceLock;

use block_appendix::BlockAppendix;
use block_appendix::MAX_NUM_CLAIMS;
use block_body::BlockBody;
use block_header::BlockHeader;
use block_height::BlockHeight;
use block_kernel::BlockKernel;
use block_validation_error::BlockValidationError;
use difficulty_control::Difficulty;
use get_size2::GetSize;
use itertools::Itertools;
use mutator_set_update::MutatorSetUpdate;
use num_traits::Zero;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tracing::warn;
use validity::block_program::BlockProgram;

use super::transaction::transaction_kernel::TransactionKernelProxy;
use super::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::block::block_header::BlockHeaderField;
use crate::block::block_header::BlockPow;
use crate::block::block_kernel::BlockKernelField;
use crate::block::difficulty_control::difficulty_control;
use crate::block::pow::PowMastPaths;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::mutator_set::addition_record::AdditionRecord;
use crate::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::mutator_set::removal_record::removal_record_list::RemovalRecordList;
use crate::network::Network;
use crate::proof_abstractions::mast_hash::HasDiscriminant;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::proof_abstractions::timestamp::Timestamp;
use crate::transaction::validity::nyks_proof::NyksProof;

/// With removal records only represented by their absolute index set, the block
/// size limit of 1.000.000 `BFieldElement`s allows for a "balanced" block
/// (equal number of inputs and outputs, no announcements) of ~10.000
/// input and outputs. To prevent an attacker from making it costly to run an
/// archival node, the number of outputs is restricted. For simplicity though
/// this limit is enforced for inputs, outputs, and announcements. This
/// restriction on the number of announcements also makes it feasible for
/// wallets to scan through all.
pub const MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS: usize = 1 << 14;

/// Duration of timelock for half of composer mining rewards.
///
/// Half the block subsidy is liquid immediately. Half of it is locked for this
/// time period.
pub const MINING_REWARD_TIME_LOCK_PERIOD: Timestamp = Timestamp::months(1);

/// Block reward per month (generation), in coins, as a lookup table.
///
/// Index = generation number (= block height's generation).
/// Values are the continuous-approximation schedule agreed on at protocol
/// design time.  Once the index exceeds the last entry the tail-emission
/// constant [`TAIL_EMISSION_BLOCK_SUBSIDY`] applies.
///
/// Generated from:
///   reward[0] = 12_800
///   reward[n] = 12_800 * exp(-k * n/12)   where k = ln(12_800/256) / 7
///   clamped to 256 at tail (generation 84+)
const BLOCK_SUBSIDY_BY_GENERATION: [u64; 84] = [
    12_800, // gen 0
    12_217, // gen 1  (rounded down)
    11_661, // gen 2
    11_130, // gen 3
    10_624, // gen 4
    10_141, // gen 5
    9_679,  // gen 6
    9_239,  // gen 7
    8_818,  // gen 8
    8_417,  // gen 9
    8_034,  // gen 10
    7_668,  // gen 11
    7_319,  // gen 12
    6_986,  // gen 13
    6_668,  // gen 14
    6_365,  // gen 15
    6_075,  // gen 16
    5_799,  // gen 17
    5_535,  // gen 18
    5_283,  // gen 19
    5_043,  // gen 20
    4_813,  // gen 21
    4_594,  // gen 22
    4_385,  // gen 23
    4_185,  // gen 24
    3_995,  // gen 25
    3_813,  // gen 26
    3_640,  // gen 27
    3_474,  // gen 28
    3_316,  // gen 29
    3_165,  // gen 30
    3_021,  // gen 31
    2_883,  // gen 32
    2_752,  // gen 33
    2_627,  // gen 34
    2_507,  // gen 35
    2_393,  // gen 36
    2_284,  // gen 37
    2_180,  // gen 38
    2_081,  // gen 39
    1_986,  // gen 40
    1_896,  // gen 41
    1_810,  // gen 42
    1_727,  // gen 43
    1_649,  // gen 44
    1_574,  // gen 45
    1_502,  // gen 46
    1_434,  // gen 47
    1_368,  // gen 48
    1_306,  // gen 49
    1_247,  // gen 50
    1_190,  // gen 51
    1_136,  // gen 52
    1_084,  // gen 53
    1_035,  // gen 54
    988,    // gen 55
    943,    // gen 56
    900,    // gen 57
    859,    // gen 58
    820,    // gen 59
    782,    // gen 60
    747,    // gen 61
    713,    // gen 62
    680,    // gen 63
    649,    // gen 64
    620,    // gen 65
    591,    // gen 66
    565,    // gen 67
    539,    // gen 68
    514,    // gen 69
    491,    // gen 70
    469,    // gen 71
    447,    // gen 72
    427,    // gen 73
    407,    // gen 74
    389,    // gen 75
    371,    // gen 76
    354,    // gen 77
    338,    // gen 78
    323,    // gen 79
    308,    // gen 80
    294,    // gen 81
    280,    // gen 82
    268,    // gen 83
            // generation 84+ -> tail emission (256)
];
pub(crate) const TAIL_EMISSION_BLOCK_SUBSIDY: NativeCurrencyAmount =
    NativeCurrencyAmount::coins(256);

/// Blocks with timestamps too far into the future are invalid. Reject blocks
/// whose timestamp exceeds now with this value or more.
pub const FUTUREDATING_LIMIT: Timestamp = Timestamp::minutes(5);

/// The size of the premine, 800 million coins.
pub const PREMINE_MAX_SIZE: NativeCurrencyAmount = NativeCurrencyAmount::coins(800_000_000);

/// All blocks have proofs except the genesis block
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize, Default)]
pub enum BlockProof {
    Genesis,
    #[default]
    Invalid,
    SingleProof(NyksProof),
}

/// Public fields of `Block` are read-only, enforced by #[readonly::make].
/// Modifications are possible only through `Block` methods.
// ## About the private `digest` field:
//
// The `digest` field represents the `Block` hash.  It is an optimization so
// that the hash can be lazily computed at most once (per modification).
//
// It is wrapped in `OnceLock<_>` for interior mutability because (a) the hash()
// method is used in many methods that are `&self` and (b) because `Block` is
// passed between tasks/threads, and thus `Rc<RefCell<_>>` is not an option.
//
// The field must be reset whenever the Block is modified.  As such, we should
// not permit direct modification of internal fields, particularly `kernel`
//
// Therefore `[readonly::make]` is used to make public `Block` fields read-only
// (not mutable) outside of this module.  All methods that modify Block also
// reset the `digest` field.
//
// We manually implement `PartialEq` and `Eq` so that digest field will not be
// compared.  Otherwise, we could have identical blocks except one has
// initialized digest field and the other has not.
//
// The field should not be serialized, so it has the `#[serde(skip)]` attribute.
// Upon deserialization, the field will have Digest::default() which is desired
// so that the digest will be recomputed if/when hash() is called.
//
// We likewise skip the field for `BFieldCodec`, and `GetSize` because there
// exist no impls for `OnceLock<_>` so derive fails.
//
// A unit test-suite exists in module tests::digest_encapsulation.
#[readonly::make]
#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct Block {
    /// Everything but the proof
    pub kernel: BlockKernel,

    pub proof: BlockProof,

    // this is only here as an optimization for Block::hash()
    // so that we lazily compute the hash at most once.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[get_size(ignore)]
    digest: OnceLock<Digest>,
}

impl MastHash for Block {
    type FieldEnum = BlockField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        vec![self.kernel.mast_hash().encode(), self.proof.encode()]
    }
}

#[derive(Debug, Copy, Clone, EnumCount)]
pub enum BlockField {
    Kernel,
    Proof,
}

impl HasDiscriminant for BlockField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        // TBD: is it faster overall to compare hashes or equality
        // of kernel and blocktype fields?
        // In the (common?) case where hash has already been
        // computed for both `Block` comparing hash equality
        // should be faster.
        self.hash() == other.hash()
    }
}
impl Eq for Block {}

impl Block {
    /// Returns the block Digest
    ///
    /// performance note:
    ///
    /// The digest is never computed until hash() is called.  Subsequent calls
    /// will not recompute it unless the Block was modified since the last call.
    #[inline]
    pub fn hash(&self) -> Digest {
        *self.digest.get_or_init(|| self.mast_hash())
    }

    #[inline]
    fn unset_digest(&mut self) {
        // note: this replaces the OnceLock so the digest will be calc'd in hash()
        self.digest = Default::default();
    }

    /// Set the guesser receiver data in the block's header.
    ///
    /// Note: this causes the block digest to change.
    #[inline]
    pub fn set_header_guesser_receiver_data(
        &mut self,
        privacy_digest: Digest,
        lock_script_hash: Digest,
    ) {
        self.kernel.header.guesser_receiver_data.receiver_digest = privacy_digest;
        self.kernel.header.guesser_receiver_data.lock_script_hash = lock_script_hash;
        self.unset_digest();
    }

    /// sets header timestamp and difficulty.
    ///
    /// These must be set as a pair because the difficulty depends
    /// on the timestamp, and may change with it.
    ///
    /// note: this causes block digest to change.
    #[inline]
    pub fn set_header_timestamp_and_difficulty(
        &mut self,
        timestamp: Timestamp,
        difficulty: Difficulty,
    ) {
        self.kernel.header.timestamp = timestamp;
        self.kernel.header.difficulty = difficulty;

        self.unset_digest();
    }

    #[inline]
    pub fn header(&self) -> &BlockHeader {
        &self.kernel.header
    }

    #[inline]
    pub fn body(&self) -> &BlockBody {
        &self.kernel.body
    }

    /// Return the mutator set as it looks after the application of this block.
    ///
    /// Includes the guesser-fee UTXOs which are not included by the
    /// `mutator_set_accumulator` field on the block body.
    pub fn mutator_set_accumulator_after(
        &self,
    ) -> Result<MutatorSetAccumulator, BlockValidationError> {
        let guesser_fee_addition_records = self.guesser_fee_addition_records()?;
        let msa = self
            .body()
            .mutator_set_accumulator_after(guesser_fee_addition_records);

        Ok(msa)
    }

    #[inline]
    pub fn appendix(&self) -> &BlockAppendix {
        &self.kernel.appendix
    }

    /// note: this causes block digest to change to that of the new block.
    #[inline]
    pub fn set_block(&mut self, block: Block) {
        *self = block;
    }

    /// The number of coins that can be printed into existence with the mining
    /// a block with this height.
    ///
    /// Uses a pre-computed constant table for generations 0–83, then
    /// returns the flat tail-emission reward for all subsequent generations.
    pub fn block_subsidy(block_height: BlockHeight) -> NativeCurrencyAmount {
        let generation = block_height.get_generation() as usize;

        BLOCK_SUBSIDY_BY_GENERATION
            .get(generation)
            .copied()
            .map(NativeCurrencyAmount::coins)
            .unwrap_or(TAIL_EMISSION_BLOCK_SUBSIDY)
    }

    /// returns coinbase reward amount for this block.
    ///
    /// note that this amount may differ from self::block_subsidy(self.height)
    /// because a miner can choose to accept less than the calculated reward amount.
    pub fn coinbase_amount(&self) -> NativeCurrencyAmount {
        // A block must always have a Coinbase.
        // we impl this method in part to cement that guarantee.
        self.body()
            .transaction_kernel
            .coinbase
            .unwrap_or_else(NativeCurrencyAmount::zero)
    }

    pub fn genesis(network: Network) -> Self {
        let mut genesis_mutator_set = MutatorSetAccumulator::default();
        let mut genesis_tx_outputs = vec![];

        let allocations = vec![
            Digest::try_from_hex(
                "a04e994cb3c3b932041db40ae5232c427d3f6d503607b96613f4f8f9add668f02b692ebe59067d10",
            )
            .unwrap(),
            Digest::try_from_hex(
                "0b79503c2c3cff27dc97edaba224ebe458d6f6c164e16b78af2721317e229d038232b6acf792b2f9",
            )
            .unwrap(),
        ];

        for allocation in allocations {
            let addition_record = AdditionRecord::new(allocation);
            genesis_mutator_set.add(&addition_record);
            genesis_tx_outputs.push(addition_record);
        }

        let genesis_txk = TransactionKernelProxy {
            inputs: vec![],
            outputs: genesis_tx_outputs,
            fee: NativeCurrencyAmount::coins(0),
            timestamp: network.launch_date(),
            announcements: vec![],
            coinbase: Some(PREMINE_MAX_SIZE),
            mutator_set_hash: MutatorSetAccumulator::default().hash(),
            merge_bit: false,
        }
        .into_kernel();

        let body: BlockBody = BlockBody::new(
            genesis_txk,
            genesis_mutator_set.clone(),
            MmrAccumulator::new_from_leafs(vec![]),
            MmrAccumulator::new_from_leafs(vec![]),
        );
        let header = BlockHeader::genesis(network);
        let appendix = BlockAppendix::default();

        Self::new(header, body, appendix, BlockProof::Genesis)
    }

    /// sender randomness is tailored to the network. This change
    /// percolates into the mutator set hash and eventually into all transaction
    /// kernels. The net result is that broadcasting transaction on other
    /// networks invalidates the lock script proofs.
    pub fn premine_sender_randomness(network: Network) -> Digest {
        Digest::new(bfe_array![u64::from(network.id()), 0, 0, 0, 0])
    }

    pub fn new(
        header: BlockHeader,
        body: BlockBody,
        appendix: BlockAppendix,
        block_proof: BlockProof,
    ) -> Self {
        let kernel = BlockKernel::new(header, body, appendix);
        Self {
            digest: OnceLock::default(), // calc'd in hash()
            kernel,
            proof: block_proof,
        }
    }

    /// Verify a block. It is assumed that `previous_block` is valid.
    /// Note that this function does **not** check that the block has enough
    /// proof of work; that must be done separately by the caller, for instance
    /// by calling [`Self::has_proof_of_work`].
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn is_valid(&self, previous_block: &Block, now: Timestamp, network: Network) -> bool {
        match self.validate(previous_block, now, network).await {
            Ok(_) => true,
            Err(e) => {
                warn!("{e}");
                false
            }
        }
    }

    /// Verify a block against previous block and return detailed error
    ///
    /// This method assumes that the previous block is valid.
    ///
    /// Note that this function does **not** check that the block has enough
    /// proof of work; that must be done separately by the caller, for instance
    /// by calling [`Self::has_proof_of_work`].
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn validate(
        &self,
        previous_block: &Block,
        now: Timestamp,
        network: Network,
    ) -> Result<(), BlockValidationError> {
        // Note that there is a correspondence between the logic here and the
        // error types in `BlockValidationError`.

        let consensus_rule_set = ConsensusRuleSet::infer_from(network, self.header().height);

        // 0.a)
        if previous_block.kernel.header.height.next() != self.kernel.header.height {
            return Err(BlockValidationError::BlockHeight);
        }

        // 0.b)
        if previous_block.hash() != self.kernel.header.prev_block_digest {
            return Err(BlockValidationError::PrevBlockDigest);
        }

        // 0.c)
        let mut mmra = previous_block.kernel.body.block_mmr_accumulator.clone();
        mmra.append(previous_block.hash());
        if mmra != self.kernel.body.block_mmr_accumulator {
            return Err(BlockValidationError::BlockMmrUpdate);
        }

        // 0.d)
        if previous_block.kernel.header.timestamp + network.minimum_block_time()
            > self.kernel.header.timestamp
        {
            return Err(BlockValidationError::MinimumBlockTime);
        }

        // 0.e)
        let expected_difficulty = if Self::should_reset_difficulty(
            network,
            self.header().timestamp,
            previous_block.header().timestamp,
        ) {
            network.genesis_difficulty()
        } else {
            difficulty_control(
                self.header().timestamp,
                previous_block.header().timestamp,
                previous_block.header().difficulty,
                network.target_block_interval(),
                previous_block.header().height,
            )
        };

        let difficulty = self.kernel.header.difficulty;
        if difficulty != expected_difficulty {
            return Err(BlockValidationError::Difficulty);
        }

        // 0.f)
        let expected_cumulative_proof_of_work =
            previous_block.header().cumulative_proof_of_work + difficulty;
        if self.header().cumulative_proof_of_work != expected_cumulative_proof_of_work {
            return Err(BlockValidationError::CumulativeProofOfWork);
        }

        // 0.g)
        let future_limit = now + FUTUREDATING_LIMIT;
        if self.kernel.header.timestamp >= future_limit {
            return Err(BlockValidationError::FutureDating);
        }

        // 1.a, 1.b, 1.c, 1.d
        self.validate_block_proof(network).await?;

        // 1.e)
        if self.size() > consensus_rule_set.max_block_size() {
            return Err(BlockValidationError::MaxSize);
        }

        // 2.a)
        let inputs = RemovalRecordList::try_unpack(self.body().transaction_kernel.inputs.clone())
            .map_err(BlockValidationError::from)?;

        // 2.b)
        let msa_before = previous_block.mutator_set_accumulator_after()?;
        for removal_record in &inputs {
            if !msa_before.can_remove(removal_record) {
                return Err(BlockValidationError::RemovalRecordsValidity);
            }
        }

        // 2.m)
        if msa_before.hash() != self.body().transaction_kernel.mutator_set_hash {
            return Err(BlockValidationError::TransactionMutatorSetMismatch);
        }

        // 2.c)
        let mut absolute_index_sets = inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices.to_vec())
            .collect_vec();
        absolute_index_sets.sort();
        absolute_index_sets.dedup();
        if absolute_index_sets.len() != inputs.len() {
            return Err(BlockValidationError::RemovalRecordsUniqueness);
        }

        let mutator_set_update = MutatorSetUpdate::new(
            inputs.clone(),
            self.body().transaction_kernel.outputs.clone(),
        );
        let mut msa = msa_before;
        let ms_update_result = mutator_set_update.apply_to_accumulator(&mut msa);

        // 2.d)
        if ms_update_result.is_err() {
            return Err(BlockValidationError::MutatorSetUpdateImpossible);
        };

        // 2.e)
        if msa.hash() != self.body().mutator_set_accumulator.hash() {
            return Err(BlockValidationError::MutatorSetUpdateIntegrity);
        }

        // 2.f)
        if self.kernel.body.transaction_kernel.timestamp > self.kernel.header.timestamp {
            return Err(BlockValidationError::TransactionTimestamp);
        }

        let block_subsidy = Self::block_subsidy(self.kernel.header.height);
        let coinbase = self.kernel.body.transaction_kernel.coinbase;
        if let Some(coinbase) = coinbase {
            // 2.g)
            if coinbase > block_subsidy {
                return Err(BlockValidationError::CoinbaseTooBig);
            }

            // 2.h)
            if coinbase.is_negative() {
                return Err(BlockValidationError::NegativeCoinbase);
            }
        }

        // 2.i)
        let fee = self.kernel.body.transaction_kernel.fee;
        if fee.is_negative() {
            return Err(BlockValidationError::NegativeFee);
        }

        // 2.j)
        if inputs.len() > consensus_rule_set.max_num_inputs() {
            return Err(BlockValidationError::TooManyInputs);
        }

        // 2.k)
        if self.body().transaction_kernel.outputs.len() > consensus_rule_set.max_num_outputs() {
            return Err(BlockValidationError::TooManyOutputs);
        }

        // 2.l)
        if self.body().transaction_kernel.announcements.len()
            > consensus_rule_set.max_num_announcements()
        {
            return Err(BlockValidationError::TooManyAnnouncements);
        }

        Ok(())
    }

    /// Validate the proof of a block, an that the proof relates to the expected
    /// appendices.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn validate_block_proof(&self, network: Network) -> Result<(), BlockValidationError> {
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, self.header().height);

        // 1.a)
        for required_claim in BlockAppendix::consensus_claims(self.body(), consensus_rule_set) {
            if !self.appendix().contains(&required_claim) {
                return Err(BlockValidationError::AppendixMissingClaim);
            }
        }

        // 1.b)
        if self.appendix().len() > MAX_NUM_CLAIMS {
            return Err(BlockValidationError::AppendixTooLarge);
        }

        // 1.c)
        let BlockProof::SingleProof(block_proof) = &self.proof else {
            return Err(BlockValidationError::ProofQuality);
        };

        // 1.d)
        if !BlockProgram::verify(self.body(), self.appendix(), block_proof, network).await {
            return Err(BlockValidationError::ProofValidity);
        }

        Ok(())
    }

    /// indicates if a difficulty reset should be performed.
    ///
    /// Reset only occurs for network(s) that define a difficulty-reset-interval,
    /// typically testnet(s).
    ///
    /// A reset should be performed any time the interval between a block
    /// and its parent block is >= the network's reset interval.
    pub fn should_reset_difficulty(
        network: Network,
        current_block_timestamp: Timestamp,
        previous_block_timestamp: Timestamp,
    ) -> bool {
        let Some(reset_interval) = network.difficulty_reset_interval() else {
            return false;
        };
        let elapsed_interval = current_block_timestamp - previous_block_timestamp;
        elapsed_interval >= reset_interval
    }

    /// Determine whether the proof-of-work puzzle was solved correctly.
    ///
    /// Specifically, compare the hash of the current block against the
    /// target corresponding to the previous block's difficulty and return true
    /// if the former is smaller.
    pub fn has_proof_of_work(&self, network: Network, previous_block_header: &BlockHeader) -> bool {
        // enforce network difficulty-reset-interval if present. Note that *no*
        // pow checks are enforced in this case, not even Merkle authentication
        // path checks. Consequently, very little memory is required to produce
        // blocks on networks that reset difficulty.
        if Self::should_reset_difficulty(
            network,
            self.header().timestamp,
            previous_block_header.timestamp,
        ) && self.header().difficulty == network.genesis_difficulty()
        {
            return true;
        }

        // Reject values that the difficulty control mechanism can never
        // produce, rather than dividing by zero.
        if self.header().difficulty < Difficulty::MINIMUM {
            return false;
        }

        let target = self.header().difficulty.target();
        if network.allows_mock_pow() && self.is_valid_mock_pow(target) {
            return true;
        }

        self.pow_verify(target)
    }

    /// Produce the MAST authentication paths for the `pow` field on
    /// [`BlockHeader`], against the block MAST hash.
    pub fn pow_mast_paths(&self) -> PowMastPaths {
        let pow = BlockHeader::mast_path(self.header(), BlockHeaderField::Pow)
            .try_into()
            .unwrap();
        let header = BlockKernel::mast_path(&self.kernel, BlockKernelField::Header)
            .try_into()
            .unwrap();
        let kernel = Block::mast_path(self, BlockField::Kernel)
            .try_into()
            .unwrap();

        PowMastPaths {
            pow,
            header,
            kernel,
        }
    }

    /// Mock verification of Pow. Use only on networks that allow for PoW
    /// mocking. Only checks that block hash is less than target. Does not
    /// verify other aspects of PoW.
    pub fn is_valid_mock_pow(&self, target: Digest) -> bool {
        self.hash() <= target
    }

    /// Satisfy mock-PoW, meaning that only the hash needs to be lower than the
    /// threshold, does not set valid root/authentication paths of the PoW
    /// field.
    pub fn satisfy_mock_pow(&mut self, difficulty: Difficulty, seed: [u8; 32]) {
        let mut rng = StdRng::from_seed(seed);

        // Guessing loop.
        let threshold = difficulty.target();
        while !self.is_valid_mock_pow(threshold) {
            let pow = rng.random();
            self.set_header_pow(pow);
        }
    }

    /// Verify that block digest is less than threshold and integral.
    pub fn pow_verify(&self, target: Digest) -> bool {
        let auth_paths = self.pow_mast_paths();
        self.header()
            .pow
            .validate(auth_paths, target, self.header().prev_block_digest)
            .is_ok()
    }

    pub fn set_header_pow(&mut self, pow: BlockPow) {
        self.kernel.header.pow = pow;
        self.unset_digest();
    }

    /// Evaluate the fork choice rule.
    ///
    /// Given two blocks, determine which one is more canonical. This function
    /// evaluates the following logic:
    ///  - if the height is different, prefer the block with more accumulated
    ///    proof-of-work;
    ///  - otherwise, if exactly one of the blocks' transactions has no inputs,
    ///    reject that one;
    ///  - otherwise, prefer the current tip.
    ///
    /// This function assumes the blocks are valid and have the self-declared
    /// accumulated proof-of-work.
    ///
    /// This function is called exclusively in
    /// [`GlobalState::incoming_block_is_more_canonical`][1], which is in turn
    /// called in two places:
    ///  1. In `peer_loop`, when a peer sends a block. The `peer_loop` task only
    ///     sends the incoming block to the `main_loop` if it is more canonical.
    ///  2. In `main_loop`, when it receives a block from a `peer_loop` or from
    ///     the `mine_loop`. It is possible that despite (1), race conditions
    ///     arise, and they must be solved here.
    ///
    /// [1]: crate::state::GlobalState::incoming_block_is_more_canonical
    pub fn fork_choice_rule<'a>(current_tip: &'a Self, incoming_block: &'a Self) -> &'a Self {
        if current_tip.header().height != incoming_block.header().height {
            if current_tip.header().cumulative_proof_of_work
                >= incoming_block.header().cumulative_proof_of_work
            {
                current_tip
            } else {
                incoming_block
            }
        } else if current_tip.body().transaction_kernel.inputs.is_empty() {
            incoming_block
        } else {
            current_tip
        }
    }

    /// Size in number of BFieldElements of the block
    // Why defined in terms of BFieldElements and not bytes? Anticipates
    // recursive block validation, where we need to test a block's size against
    // the limit. The size is easier to calculate if it relates to a block's
    // encoding on the VM, rather than its serialization as a vector of bytes.
    pub fn size(&self) -> usize {
        self.encode().len()
    }

    /// A number showing how big the guesser reward is relative to the block
    /// subsidy.  Notice that this number can exceed 1 because of transaction
    /// fees.
    ///
    /// May not be used in any consensus-related setting, as precision is lost
    /// because of the use of floats.
    pub fn relative_guesser_reward(&self) -> Result<f64, BlockValidationError> {
        let guesser_reward = self.body().total_guesser_reward()?;
        let block_subsidy = Self::block_subsidy(self.header().height);

        Ok(guesser_reward.to_nau_f64() / block_subsidy.to_nau_f64())
    }

    /// Compute the addition records that correspond to the UTXOs generated for
    /// the block's guesser
    ///
    /// The genesis block does not have this addition record.
    pub fn guesser_fee_addition_records(
        &self,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        let block_hash = self.hash();
        self.kernel.guesser_fee_addition_records(block_hash)
    }

    /// Return all addition records (transaction outputs) in this block,
    /// including guesser rewards.
    pub fn all_addition_records(&self) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        let block_hash = self.hash();
        self.kernel.all_addition_records(block_hash)
    }

    /// Return the mutator set update corresponding to this block, which sends
    /// the mutator set accumulator after the predecessor to the mutator set
    /// accumulator after self.
    pub fn mutator_set_update(&self) -> Result<MutatorSetUpdate, BlockValidationError> {
        let block_hash = self.hash();
        self.kernel.mutator_set_update(block_hash)
    }
}
