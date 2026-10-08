use async_trait::async_trait;
use itertools::Itertools;
use nyks_consensus::block::Block;
use nyks_consensus::block::FUTUREDATING_LIMIT;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::Transaction;
use nyks_rpc_core::api::rpc::*;
use nyks_rpc_core::model::block::header::TransactionKernelWithPriority;
use nyks_rpc_core::model::block::RpcBlock;
use nyks_rpc_core::model::common::BlockSelector;
use nyks_rpc_core::model::common::BlockSelectorLiteral;
use nyks_rpc_core::model::message::*;
use nyks_rpc_core::model::mining::mempool::RpcMempoolMetadata;
use nyks_rpc_core::model::mining::template::RpcBlockTemplate;
use nyks_rpc_core::model::mining::template::RpcBlockTemplateMetadata;
use nyks_rpc_core::model::wallet::block::RpcWalletBlock;
use nyks_rpc_core::model::wallet::mutator_set::RpcMsMembershipSnapshot;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::address::Recipient;
use tasm_lib::prelude::Digest;
use tracing::debug;

use crate::application::config::parser::multiaddr::parse_to_multiaddr;
use crate::application::loops::channel::RPCServerToMain;
use crate::application::rpc::server::RpcServer;
use crate::state::GlobalState;

async fn find_block_digest(selector: BlockSelector, state: &GlobalState) -> Option<Digest> {
    match selector {
        BlockSelector::Special(BlockSelectorLiteral::Tip) => Some(state.chain.tip().hash()),
        BlockSelector::Special(BlockSelectorLiteral::Genesis) => {
            Some(state.chain.archival_state().genesis_block().hash())
        }
        BlockSelector::Digest(d) => Some(d),
        BlockSelector::Height(h) => {
            state
                .chain
                .archival_state()
                .archival_block_mmr
                .ammr()
                .try_get_leaf((h).into())
                .await
        }
    }
}

#[async_trait]
impl RpcApi for RpcServer {
    async fn network_call(&self, _: NetworkRequest) -> RpcResult<NetworkResponse> {
        Ok(NetworkResponse {
            network: self.state.cli().network.into(),
        })
    }

    async fn height_call(&self, _: HeightRequest) -> RpcResult<HeightResponse> {
        let state = self.state.lock_guard().await;

        Ok(HeightResponse {
            height: state.chain.tip().kernel.header.height,
        })
    }

    async fn tip_digest_call(&self, _: TipDigestRequest) -> RpcResult<TipDigestResponse> {
        let state = self.state.lock_guard().await;
        let block = state.chain.tip();

        Ok(TipDigestResponse {
            digest: block.hash(),
        })
    }

    async fn tip_call(&self, _: TipRequest) -> RpcResult<TipResponse> {
        let state = self.state.lock_guard().await;
        let block = state.chain.tip();

        Ok(TipResponse {
            block: block.into(),
        })
    }

    async fn tip_proof_call(&self, _: TipProofRequest) -> RpcResult<TipProofResponse> {
        let state = self.state.lock_guard().await;
        let proof = &state.chain.tip().proof;

        Ok(TipProofResponse {
            proof: proof.into(),
        })
    }

    async fn tip_kernel_call(&self, _: TipKernelRequest) -> RpcResult<TipKernelResponse> {
        let state = self.state.lock_guard().await;
        let kernel = &state.chain.tip().kernel;

        Ok(TipKernelResponse {
            kernel: kernel.into(),
        })
    }

    async fn tip_header_call(&self, _: TipHeaderRequest) -> RpcResult<TipHeaderResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipHeaderResponse {
            header: state.chain.tip().header().into(),
        })
    }

    async fn tip_body_call(&self, _: TipBodyRequest) -> RpcResult<TipBodyResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipBodyResponse {
            body: state.chain.tip().body().into(),
        })
    }

    async fn tip_transaction_kernel_call(
        &self,
        _: TipTransactionKernelRequest,
    ) -> RpcResult<TipTransactionKernelResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipTransactionKernelResponse {
            kernel: state.chain.tip().body().transaction_kernel().into(),
        })
    }

    async fn tip_announcements_call(
        &self,
        _: TipAnnouncementsRequest,
    ) -> RpcResult<TipAnnouncementsResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipAnnouncementsResponse {
            announcements: state
                .chain
                .tip()
                .body()
                .transaction_kernel()
                .announcements
                .iter()
                .map(|a| a.clone().into())
                .collect(),
        })
    }

    async fn get_block_digest_call(
        &self,
        request: GetBlockDigestRequest,
    ) -> RpcResult<GetBlockDigestResponse> {
        let state = self.state.lock_guard().await;
        let digest = find_block_digest(request.selector, &state).await;

        Ok(GetBlockDigestResponse { digest })
    }

    async fn get_block_digests_call(
        &self,
        request: GetBlockDigestsRequest,
    ) -> RpcResult<GetBlockDigestsResponse> {
        let state = self.state.lock_guard().await;

        Ok(GetBlockDigestsResponse {
            digests: state
                .chain
                .archival_state()
                .block_height_to_block_digests(request.height.into())
                .await,
        })
    }

    async fn get_block_call(&self, request: GetBlockRequest) -> RpcResult<GetBlockResponse> {
        let state = self.state.lock_guard().await;

        let digest = find_block_digest(request.selector, &state).await;
        let block = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(RpcBlock::from),
            None => None,
        };

        Ok(GetBlockResponse { block })
    }

    async fn get_block_proof_call(
        &self,
        request: GetBlockProofRequest,
    ) -> RpcResult<GetBlockProofResponse> {
        let state = self.state.lock_guard().await;

        let digest = find_block_digest(request.selector, &state).await;
        let proof = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| (&b.proof).into()),
            None => None,
        };

        Ok(GetBlockProofResponse { proof })
    }

    async fn get_block_kernel_call(
        &self,
        request: GetBlockKernelRequest,
    ) -> RpcResult<GetBlockKernelResponse> {
        let state = self.state.lock_guard().await;

        let digest = find_block_digest(request.selector, &state).await;
        let kernel = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| (&b.kernel).into()),
            None => None,
        };

        Ok(GetBlockKernelResponse { kernel })
    }

    async fn get_block_header_call(
        &self,
        request: GetBlockHeaderRequest,
    ) -> RpcResult<GetBlockHeaderResponse> {
        let state = self.state.lock_guard().await;

        let digest = find_block_digest(request.selector, &state).await;
        let header = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.header().into()),
            None => None,
        };

        Ok(GetBlockHeaderResponse { header })
    }

    async fn get_block_body_call(
        &self,
        request: GetBlockBodyRequest,
    ) -> RpcResult<GetBlockBodyResponse> {
        let state = self.state.lock_guard().await;

        let digest = find_block_digest(request.selector, &state).await;
        let body = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.body().into()),
            None => None,
        };

        Ok(GetBlockBodyResponse { body })
    }

    async fn get_block_transaction_kernel_call(
        &self,
        request: GetBlockTransactionKernelRequest,
    ) -> RpcResult<GetBlockTransactionKernelResponse> {
        let state = self.state.lock_guard().await;

        let digest = find_block_digest(request.selector, &state).await;
        let kernel = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.body().transaction_kernel().into()),
            None => None,
        };

        Ok(GetBlockTransactionKernelResponse { kernel })
    }

    async fn get_block_announcements_call(
        &self,
        request: GetBlockAnnouncementsRequest,
    ) -> RpcResult<GetBlockAnnouncementsResponse> {
        let state = self.state.lock_guard().await;

        let digest = find_block_digest(request.selector, &state).await;
        let announcements = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| {
                    b.body()
                        .transaction_kernel()
                        .announcements
                        .iter()
                        .map(|a| a.clone().into())
                        .collect::<Vec<_>>()
                }),
            None => None,
        };

        Ok(GetBlockAnnouncementsResponse { announcements })
    }

    async fn is_block_canonical_call(
        &self,
        request: IsBlockCanonicalRequest,
    ) -> RpcResult<IsBlockCanonicalResponse> {
        let state = self.state.lock_guard().await;

        let block_hash = request.digest;
        let is_canonical = state
            .chain
            .archival_state()
            .block_belongs_to_canonical_chain(block_hash)
            .await;

        Ok(IsBlockCanonicalResponse {
            canonical: is_canonical,
        })
    }

    async fn get_utxo_digest_call(
        &self,
        request: GetUtxoDigestRequest,
    ) -> RpcResult<GetUtxoDigestResponse> {
        let state = self.state.lock_guard().await;
        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;

        Ok(GetUtxoDigestResponse {
            digest: aocl.try_get_leaf(request.leaf_index).await,
        })
    }

    async fn are_bloom_indices_set_call(
        &self,
        request: AreBloomIndicesSetRequest,
    ) -> RpcResult<AreBloomIndicesSetResponse> {
        Ok(AreBloomIndicesSetResponse {
            are_set: self
                .state
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .absolute_index_set_was_applied(request.absolute_index_set)
                .await,
        })
    }

    /* wallet */

    async fn get_blocks_call(&self, request: GetBlocksRequest) -> RpcResult<GetBlocksResponse> {
        if request.to_height < request.from_height || request.from_height.is_genesis() {
            return Ok(GetBlocksResponse {
                blocks: Vec::default(),
            });
        }

        let max_blocks = if self.unrestricted { usize::MAX } else { 100 };

        let state = self.state.lock_guard().await;
        let mut blocks = Vec::new();
        let mut height = request.from_height;

        while height <= request.to_height && blocks.len() < max_blocks {
            let block_selector = BlockSelector::Height(height);
            let Some(block_hash) = find_block_digest(block_selector, &state).await else {
                break;
            };

            // Avoid having to recalculate hash of block proof again, as that's
            // expensive. Use the archival state's full capabilities to get the
            // hashed proof from its state.
            let Some((block, proof_digest)) = state
                .chain
                .archival_state()
                .get_block_kernel_with_proof_digest(block_hash)
                .await
                .unwrap()
            else {
                break;
            };

            let block = RpcWalletBlock {
                kernel: (&block).into(),
                proof_leaf: proof_digest
                    .expect("Every block except genesis must have a proof digest leaf"),
            };

            debug_assert_eq!(
                block_hash,
                block.hash(),
                "Conversion to wallet block must preserve block hash"
            );

            blocks.push(block);
            height = height.next();
        }

        Ok(GetBlocksResponse { blocks })
    }

    async fn restore_membership_proof_call(
        &self,
        request: RestoreMembershipProofRequest,
    ) -> RpcResult<RestoreMembershipProofResponse> {
        if request.absolute_index_sets.len() > 256 && !self.unrestricted {
            return Err(RpcError::RestoreMembershipProof(
                RestoreMembershipProofError::ExceedsAllowed,
            ));
        }

        let state = self.state.lock_guard().await;
        let ams = state.chain.archival_state().archival_mutator_set.ams();
        let mut membership_proofs = Vec::with_capacity(request.absolute_index_sets.len());

        for (index, set) in request.absolute_index_sets.into_iter().enumerate() {
            match ams.restore_membership_proof_privacy_preserving(set).await {
                Ok(msmp) => membership_proofs.push(msmp.into()),
                Err(err) => {
                    debug!("Failed to restore MSMP for {index}: {err}");
                    return Err(RpcError::RestoreMembershipProof(
                        RestoreMembershipProofError::Failed(index),
                    ));
                }
            }
        }

        let tip_height = state.chain.tip_height();
        let tip_hash = state.chain.tip_hash();
        let tip_mutator_set = state.chain.tip_mutator_set_after();
        let snapshot = RpcMsMembershipSnapshot {
            synced_height: tip_height.into(),
            synced_hash: tip_hash,
            membership_proofs,
            synced_mutator_set: (&tip_mutator_set).into(),
        };

        Ok(RestoreMembershipProofResponse { snapshot })
    }

    async fn submit_transaction_call(
        &self,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse> {
        let transaction: Transaction = request.transaction.into();
        let network = self.state.cli().network;
        let consensus_rule_set = self.state.lock_guard().await.consensus_rule_set();

        if !transaction.is_valid(network, consensus_rule_set).await {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::InvalidTransaction,
            ));
        }

        if transaction.kernel.coinbase.is_some() {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::CoinbaseTransaction,
            ));
        }

        if transaction.kernel.fee.is_negative() {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::FeeNegative,
            ));
        }

        let timestamp = transaction.kernel.timestamp;
        let now = Timestamp::now();
        if timestamp >= now + FUTUREDATING_LIMIT {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::FutureDated,
            ));
        }

        let msa = self.state.lock_guard().await.chain.tip_mutator_set_after();
        if !transaction.is_confirmable_relative_to(&msa) {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::NotConfirmable,
            ));
        }

        let success = self
            .to_main_tx
            .send(RPCServerToMain::BroadcastTx(Box::new(transaction)))
            .await
            .is_ok();

        Ok(SubmitTransactionResponse { success })
    }

    /* Mining */

    async fn submit_block_template_call(
        &self,
        request: SubmitBlockTemplateRequest,
    ) -> RpcResult<SubmitBlockTemplateResponse> {
        // Is the proposal valid?
        // Lock needs to be held here because race conditions: otherwise
        // the block proposal that was validated might not match with
        // the one whose favorability is being computed.
        let state = self.state.lock_guard().await;
        let tip = state.chain.tip();
        let template: Block = request.block.into();
        let is_valid = template
            .is_valid(tip, Timestamp::now(), state.cli().network)
            .await;
        if !is_valid {
            return Err(RpcError::SubmitBlock(SubmitBlockError::InvalidBlock));
        }

        // Is block proposal favorable?
        let is_favorable = state.favor_incoming_block_proposal(
            template.header().prev_block_digest,
            template
                .body()
                .total_guesser_reward()
                .expect("Block was validated"),
        );
        drop(state);

        if let Err(_) = is_favorable {
            return Ok(SubmitBlockTemplateResponse { success: false });
        }

        // No time to waste! Inform main_loop!
        let template = Box::new(template);
        let success = self
            .to_main_tx
            .send(RPCServerToMain::BlockProposal(template))
            .await
            .is_ok();

        Ok(SubmitBlockTemplateResponse { success })
    }

    async fn get_block_template_call(
        &self,
        request: GetBlockTemplateRequest,
    ) -> RpcResult<GetBlockTemplateResponse> {
        let maybe_proposal = {
            let global_state = self.state.lock_guard().await;
            global_state.mining_state.block_proposal.map(|p| p.clone())
        };

        let Some(mut proposal) = maybe_proposal else {
            return Ok(GetBlockTemplateResponse { template: None });
        };

        if let Some(address) = request.guesser_address {
            let address = Address::from_bech32m(&address, self.state.cli().network)
                .map_err(|_| RpcError::InvalidAddress)?;
            proposal.set_header_guesser_receiver_data(
                address.privacy_digest(),
                address.lock_script().hash(),
            );
        }

        let template = RpcBlockTemplate {
            block: RpcBlock::from(&proposal),
            metadata: RpcBlockTemplateMetadata::new(&proposal),
        };

        Ok(GetBlockTemplateResponse {
            template: Some(template),
        })
    }

    async fn submit_block_call(
        &self,
        request: SubmitBlockRequest,
    ) -> RpcResult<SubmitBlockResponse> {
        let mut template: Block = request.template.into();

        // Since block comes from external source, we need to check validity.
        let tip = self.state.lock_guard().await.chain.tip().clone();
        if !template
            .is_valid(&tip, Timestamp::now(), self.state.cli().network)
            .await
        {
            return Err(RpcError::SubmitBlock(SubmitBlockError::InvalidBlock));
        }

        template.set_header_pow(request.pow.into());

        if !template.has_proof_of_work(self.state.cli().network, template.header()) {
            return Err(RpcError::SubmitBlock(SubmitBlockError::InsufficientWork));
        }

        // No time to waste! Inform main_loop!
        let solution = Box::new(template);
        let success = self
            .to_main_tx
            .send(RPCServerToMain::ProofOfWorkSolution(solution))
            .await
            .is_ok();

        Ok(SubmitBlockResponse { success })
    }

    /* Mempool */

    async fn transactions_call(&self, _: TransactionsRequest) -> RpcResult<TransactionsResponse> {
        let state = self.state.lock_guard().await;

        let transactions = state
            .mempool
            .fee_density_iter()
            .map(|(txkid, _)| txkid)
            .collect();
        let metadata = RpcMempoolMetadata {
            tip_mutator_set_hash: *state.mempool.tip_mutator_set_hash(),
        };

        Ok(TransactionsResponse {
            transactions,
            metadata,
        })
    }

    async fn get_transaction_call(
        &self,
        request: GetTransactionRequest,
    ) -> RpcResult<GetTransactionResponse> {
        let transaction = self
            .state
            .lock_guard()
            .await
            .mempool
            .get(request.id)
            .cloned();

        Ok(GetTransactionResponse {
            transaction: transaction.map(|t| t.into()),
        })
    }

    async fn get_transaction_kernel_call(
        &self,
        request: GetTransactionKernelRequest,
    ) -> RpcResult<GetTransactionKernelResponse> {
        let transaction = self
            .state
            .lock_guard()
            .await
            .mempool
            .get(request.id)
            .cloned();

        Ok(GetTransactionKernelResponse {
            kernel: transaction.map(|t| (&t.kernel).into()),
        })
    }

    async fn get_transaction_proof_call(
        &self,
        request: GetTransactionProofRequest,
    ) -> RpcResult<GetTransactionProofResponse> {
        let transaction = self
            .state
            .lock_guard()
            .await
            .mempool
            .get(request.id)
            .cloned();

        Ok(GetTransactionProofResponse {
            proof: transaction.map(|t| t.proof.into()),
        })
    }

    async fn get_transactions_by_addition_records_call(
        &self,
        request: GetTransactionsByAdditionRecordsRequest,
    ) -> RpcResult<GetTransactionsByAdditionRecordsResponse> {
        let addition_records = request
            .addition_records
            .into_iter()
            .map(|x| x.into())
            .collect();
        let transactions = self
            .state
            .lock_guard()
            .await
            .mempool
            .with_matching_addition_records(&addition_records);

        let transactions = transactions
            .into_iter()
            .map(|(tx_kernel, queue_order)| {
                TransactionKernelWithPriority::new(
                    &tx_kernel,
                    queue_order.map(|order| {
                        u32::try_from(order)
                            .expect("Cannot have more than u32::MAX transactions in mempool")
                    }),
                )
            })
            .collect_vec();
        let transactions = GetTransactionsByAdditionRecordsResponse { transactions };

        Ok(transactions)
    }

    async fn get_transactions_by_absolute_index_sets_call(
        &self,
        request: GetTransactionsByAbsoluteIndexSetsRequest,
    ) -> RpcResult<GetTransactionsByAbsoluteIndexSetsResponse> {
        let absolute_index_sets = request.absolute_index_sets.into_iter().collect();
        let transactions = self
            .state
            .lock_guard()
            .await
            .mempool
            .with_matching_absolute_index_sets(&absolute_index_sets);

        let transactions = transactions
            .into_iter()
            .map(|(tx_kernel, queue_order)| {
                TransactionKernelWithPriority::new(
                    &tx_kernel,
                    queue_order.map(|order| {
                        u32::try_from(order)
                            .expect("Cannot have more than u32::MAX transactions in mempool")
                    }),
                )
            })
            .collect_vec();
        let transactions = GetTransactionsByAbsoluteIndexSetsResponse { transactions };

        Ok(transactions)
    }

    async fn best_transaction_for_next_block_call(
        &self,
        _: BestTransactionForNextBlockRequest,
    ) -> RpcResult<BestTransactionForNextBlockResponse> {
        let tx = self
            .state
            .lock_guard()
            .await
            .mempool
            .get_transactions_for_block_composition(usize::MAX, Some(1));
        let tx = tx.first();
        let tx = BestTransactionForNextBlockResponse {
            transaction: tx.map(|tx| (&tx.kernel).into()),
        };

        Ok(tx)
    }

    async fn ban_call(&self, request: BanRequest) -> RpcResult<BanResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let address =
            parse_to_multiaddr(&request.address).map_err(|_| RpcError::InvalidMultiaddr)?;
        let _ = self.to_main_tx.send(RPCServerToMain::Ban(address)).await;

        Ok(BanResponse {})
    }

    async fn unban_call(&self, request: UnbanRequest) -> RpcResult<UnbanResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let address =
            parse_to_multiaddr(&request.address).map_err(|_| RpcError::InvalidMultiaddr)?;
        let _ = self.to_main_tx.send(RPCServerToMain::Unban(address)).await;

        Ok(UnbanResponse {})
    }

    async fn unban_all_call(&self, _request: UnbanAllRequest) -> RpcResult<UnbanAllResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self.to_main_tx.send(RPCServerToMain::UnbanAll).await;

        Ok(UnbanAllResponse {})
    }

    async fn dial_call(&self, request: DialRequest) -> RpcResult<DialResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let address =
            parse_to_multiaddr(&request.address).map_err(|_| RpcError::InvalidMultiaddr)?;
        let _ = self.to_main_tx.send(RPCServerToMain::Dial(address)).await;

        Ok(DialResponse {})
    }

    async fn probe_nat_call(&self, _request: ProbeNatRequest) -> RpcResult<ProbeNatResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self.to_main_tx.send(RPCServerToMain::ProbeNat).await;

        Ok(ProbeNatResponse {})
    }

    async fn reset_relay_reservations_call(
        &self,
        _request: ResetRelayReservationsRequest,
    ) -> RpcResult<ResetRelayReservationsResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::ResetRelayReservations)
            .await;

        Ok(ResetRelayReservationsResponse {})
    }
}
