pub mod change_policy;
pub mod input;
pub mod output;

use num_traits::Zero;

use nyks_consensus::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::announcement::Announcement;
use nyks_consensus::transaction::transaction_kernel::TransactionKernelProxy;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use thiserror::Error;

use crate::transaction::BuilderTransaction;
use crate::transaction::builder::input::TxInputList;
use crate::transaction::builder::output::TxOutputList;
use crate::transaction::primitive_witness::PrimitiveWitness;

#[derive(Debug, Clone, Copy, Error)]
pub enum TransactionBuildError {
    #[error("missing inputs")]
    MissingInputs,

    #[error("missing outputs")]
    MissingOutputs,

    #[error("missing mutator set accumulator")]
    MissingMutatorSetAccumulator,
}

#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    inputs: Option<TxInputList>,
    outputs: Option<TxOutputList>,
    fee: NativeCurrencyAmount,
    coinbase: Option<NativeCurrencyAmount>,
    timestamp: Option<Timestamp>,
    mutator_set_accumulator: Option<MutatorSetAccumulator>,
    announcements: Vec<Announcement>,
}

// Builder interface
impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            inputs: None,
            outputs: None,
            fee: NativeCurrencyAmount::zero(),
            coinbase: None,
            timestamp: None,
            mutator_set_accumulator: None,
            announcements: Vec::new(),
        }
    }

    pub fn inputs(mut self, inputs: TxInputList) -> Self {
        self.inputs = Some(inputs);
        self
    }

    pub fn outputs(mut self, outputs: TxOutputList) -> Self {
        self.outputs = Some(outputs);
        self
    }

    pub fn fee(mut self, fee: NativeCurrencyAmount) -> Self {
        self.fee = fee;
        self
    }

    pub fn coinbase(mut self, amount: NativeCurrencyAmount) -> Self {
        self.coinbase = Some(amount);
        self
    }

    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn mutator_set_accumulator(mut self, msa: MutatorSetAccumulator) -> Self {
        self.mutator_set_accumulator = Some(msa);
        self
    }

    /// Add public announcements before output notification announcements.
    pub fn custom_announcements(mut self, announcements: Vec<Announcement>) -> Self {
        self.announcements = announcements;
        self
    }
}

impl TransactionBuilder {
    // TODO: ChangePolicy
    pub fn build(self) -> Result<BuilderTransaction, TransactionBuildError> {
        let inputs = self.inputs.ok_or(TransactionBuildError::MissingInputs)?;
        let outputs = self.outputs.ok_or(TransactionBuildError::MissingOutputs)?;
        let timestamp = self.timestamp.unwrap_or_else(Timestamp::now);
        let msa = self
            .mutator_set_accumulator
            .ok_or(TransactionBuildError::MissingMutatorSetAccumulator)?;

        let kernel = {
            let input_records = inputs.removal_records(&msa);
            let output_records = outputs.addition_records();
            let announcements = self
                .announcements
                .into_iter()
                .chain(outputs.announcements())
                .collect();

            TransactionKernelProxy {
                inputs: input_records,
                outputs: output_records,
                announcements,
                fee: self.fee,
                coinbase: self.coinbase,
                timestamp,
                mutator_set_hash: msa.hash(),
                merge_bit: false,
            }
            .into_kernel()
        };

        let output_utxos = outputs.utxos();
        let sender_randomnesses = outputs.sender_randomnesses();
        let receiver_digests = outputs.receiver_digests();

        Ok(PrimitiveWitness::generate_primitive_witness(
            &inputs,
            output_utxos,
            sender_randomnesses,
            receiver_digests,
            kernel,
            msa,
        )
        .into())
    }
}
