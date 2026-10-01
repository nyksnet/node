use num_traits::CheckedSub;
use num_traits::Zero;
use nyks_consensus::block::Block;
use nyks_consensus::block::block_transaction::BlockOrRegularTransaction;
use nyks_consensus::block::block_transaction::BlockTransaction;
use nyks_consensus::consensus_rule_set::ConsensusRuleSet;
use nyks_consensus::proof_abstractions::SecretWitness;
use nyks_consensus::proof_abstractions::tasm::program::TritonProgram;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::Transaction;
use nyks_consensus::transaction::TransactionProof;
use nyks_consensus::transaction::validity::nyks_proof::NyksProof;
use nyks_consensus::transaction::validity::single_proof::SingleProof;
use nyks_consensus::transaction::validity::single_proof::SingleProofWitness;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_prover::JobCancelReceiver;
use nyks_prover::ProverJob;
use nyks_prover::ProverJobSettings;
use nyks_prover::ProverProcessCompletion;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;
use nyks_wallet_core::transaction::builder::TransactionBuilder;
use nyks_wallet_core::transaction::builder::input::TxInputList;
use nyks_wallet_core::transaction::builder::output::TxOutput;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use thiserror::Error;
use tracing::info;

use crate::core::args::Args;

#[derive(Debug, Error)]
pub enum TransactionProverError {
    #[error("prove cancelled")]
    Cancelled,

    #[error(transparent)]
    ProverJob(#[from] nyks_prover::ProverJobError),

    #[error(transparent)]
    VmProcess(#[from] nyks_prover::VmProcessError),
}

// Helper for creating and proving transactions for block production.
//
// Builds coinbase transactions, selects or creates a transaction to merge,
// and generates the required zero-knowledge proofs.
//
// The tip can be updated via `set_tip()` and reused.
#[derive(Clone, Debug)]
pub struct TransactionProver {
    args: Args,
    tip: Block,
    client: HttpClient,
    job_settings: ProverJobSettings,
}

impl TransactionProver {
    pub fn new(args: Args, client: HttpClient, job_settings: ProverJobSettings) -> Self {
        TransactionProver {
            tip: Block::genesis(args.network),
            args,
            client,
            job_settings,
        }
    }

    pub fn set_tip(&mut self, new_tip: Block) {
        self.tip = new_tip;
    }

    pub async fn prepare_block_transaction(
        &self,
        rx: JobCancelReceiver,
    ) -> Result<BlockTransaction, TransactionProverError> {
        let mutator_set_hash = self.tip.mutator_set_accumulator_after().unwrap().hash();

        info!(
            "Creating block transaction for mutator set hash: {:x}",
            mutator_set_hash
        );

        let block_height = self.tip.header().height.next();
        let network = self.args.network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);

        let coinbase_transaction = self.prepare_coinbase_transaction(rx.clone()).await?;
        let merge_tx = self.prepare_merge_transaction(rx.clone()).await?;

        let mut block_transaction = BlockOrRegularTransaction::from(coinbase_transaction);

        info!("Merging transactions together...");

        let mut rng = StdRng::seed_from_u64(0);
        // TODO: move to off-process...
        block_transaction = BlockTransaction::merge(
            block_transaction,
            merge_tx,
            rng.random(),
            consensus_rule_set,
        )
        .unwrap()
        .into();

        Ok(block_transaction
            .try_into()
            .expect("Must have merged at least once"))
    }

    async fn prepare_coinbase_transaction(
        &self,
        rx: JobCancelReceiver,
    ) -> Result<Transaction, TransactionProverError> {
        let timestamp = Timestamp::now();
        let mutator_set_accumulator = self.tip.mutator_set_accumulator_after().unwrap();
        let coinbase_amount = Block::block_subsidy(self.tip.header().height.next());
        let composer_outputs = self
            .args
            .tx_outputs(self.tip.hash(), coinbase_amount, timestamp);
        let total_composer_fee = composer_outputs.total_native_coins();
        let guesser_fee = coinbase_amount
            .checked_sub(&total_composer_fee)
            .expect("total_composer_fee cannot exceed coinbase_amount");

        info!(
            "Coinbase amount {coinbase_amount} NYKS distributed as composer fee ({total_composer_fee} NYKS) + guesser fee ({guesser_fee} NYKS)."
        );

        let transaction = TransactionBuilder::new()
            .inputs(TxInputList::empty())
            .outputs(composer_outputs.clone())
            .coinbase(coinbase_amount)
            .fee(guesser_fee)
            .timestamp(timestamp)
            .mutator_set_accumulator(mutator_set_accumulator)
            .build()
            .unwrap();
        let transaction = transaction.upgrade();

        info!("Starting proving coinbase transaction...");
        let single_proof_witness =
            SingleProofWitness::from_collection(transaction.proof.as_collection().unwrap());

        let proof = self
            .prove_single(
                single_proof_witness.claim(),
                single_proof_witness.nondeterminism(),
                rx,
            )
            .await?;

        info!("Generated single proof for coinbase transaction successfully!");

        Ok(Transaction {
            kernel: transaction.kernel,
            proof: TransactionProof::SingleProof(proof),
        })
    }

    async fn prepare_merge_transaction(
        &self,
        rx: JobCancelReceiver,
    ) -> Result<Transaction, TransactionProverError> {
        if let Some(tx) = self.find_mempool_merger().await {
            return Ok(tx);
        }

        info!("No usable merge transaction found on mempool, generating a nop transaction...");
        let nop = self.prepare_nop_transaction(rx).await?;

        // Re-check: a valid tx may have arrived while generating the nop.
        if let Some(tx) = self.find_mempool_merger().await {
            info!("Found mempool merger after nop generation; using it instead.");
            return Ok(tx);
        }

        Ok(nop)
    }

    /// Returns the first mempool transaction that is a single-proof valid
    /// against the current tip's mutator set, or `None` if none exists.
    async fn find_mempool_merger(&self) -> Option<Transaction> {
        let mutator_set_hash = self.tip.mutator_set_accumulator_after().unwrap().hash();
        let mempool_txs = self.client.transactions().await.unwrap().transactions;

        for tx_hash in mempool_txs {
            if let Some(tx) = self
                .client
                .get_transaction(tx_hash)
                .await
                .unwrap()
                .transaction
            {
                let tx: Transaction = tx.into();
                if tx.proof.is_single_proof() && tx.kernel.mutator_set_hash == mutator_set_hash {
                    info!("Using {} from mempool as merger.", tx_hash);
                    return Some(tx);
                }
            }
        }

        None
    }

    async fn prepare_nop_transaction(
        &self,
        rx: JobCancelReceiver,
    ) -> Result<Transaction, TransactionProverError> {
        let mutator_set_accumulator = self.tip.mutator_set_accumulator_after().unwrap();
        let transaction = TransactionBuilder::new()
            .inputs(TxInputList::empty())
            .outputs(Vec::<TxOutput>::new().into())
            .fee(NativeCurrencyAmount::zero())
            .timestamp(Timestamp::now())
            .mutator_set_accumulator(mutator_set_accumulator)
            .build()
            .unwrap();
        let transaction = transaction.upgrade();
        let single_proof_witness =
            SingleProofWitness::from_collection(transaction.proof.as_collection().unwrap());

        let proof = self
            .prove_single(
                single_proof_witness.claim(),
                single_proof_witness.nondeterminism(),
                rx,
            )
            .await?;

        Ok(Transaction {
            kernel: transaction.kernel,
            proof: TransactionProof::SingleProof(proof),
        })
    }

    /// Delegates to `ProverJob` (out-of-process), so cancellation actually
    /// kills the worker process rather than just stopping our wait on it.
    async fn prove_single(
        &self,
        claim: nyks_consensus::triton_vm::proof::Claim,
        nondeterminism: nyks_consensus::triton_vm::vm::NonDeterminism,
        rx: JobCancelReceiver,
    ) -> Result<NyksProof, TransactionProverError> {
        let job = ProverJob::new(
            SingleProof.program(),
            claim,
            nondeterminism,
            self.job_settings.clone(),
        );

        match job.prove(rx).await? {
            ProverProcessCompletion::Finished(proof) => Ok(proof),
            ProverProcessCompletion::Cancelled => Err(TransactionProverError::Cancelled),
        }
    }
}
