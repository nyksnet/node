use serde::Deserialize;
use serde::Serialize;
use serde_tuple::Deserialize_tuple;
use serde_tuple::Serialize_tuple;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::model::block::body::*;
use crate::model::block::header::*;
use crate::model::block::transaction_kernel::*;
use crate::model::block::*;
use crate::model::common::*;
use crate::model::mining::mempool::RpcMempoolMetadata;
use crate::model::mining::template::RpcBlockTemplate;
use crate::model::wallet::block::*;
use crate::model::wallet::mutator_set::*;
use crate::model::wallet::transaction::RpcTransaction;
use crate::model::wallet::transaction::RpcTransactionProof;

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResponse {
    pub network: RpcNetwork,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct HeightRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeightResponse {
    pub height: RpcBlockHeight,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipDigestRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipDigestResponse {
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipResponse {
    pub block: RpcBlock,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipProofRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipProofResponse {
    pub proof: RpcBlockProof,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipKernelRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipKernelResponse {
    pub kernel: RpcBlockKernel,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipHeaderRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipHeaderResponse {
    pub header: RpcBlockHeader,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipBodyRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipBodyResponse {
    pub body: RpcBlockBody,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipTransactionKernelRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipTransactionKernelResponse {
    pub kernel: RpcTransactionKernel,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipAnnouncementsRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipAnnouncementsResponse {
    pub announcements: Vec<RpcAnnouncement>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestRequest {
    pub selector: BlockSelector,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestResponse {
    pub digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestsRequest {
    pub height: BFieldElement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestsResponse {
    pub digests: Vec<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockRequest {
    pub selector: BlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResponse {
    pub block: Option<RpcBlock>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockProofRequest {
    pub selector: BlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockProofResponse {
    pub proof: Option<RpcBlockProof>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockKernelRequest {
    pub selector: BlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockKernelResponse {
    pub kernel: Option<RpcBlockKernel>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderRequest {
    pub selector: BlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResponse {
    pub header: Option<RpcBlockHeader>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockBodyRequest {
    pub selector: BlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockBodyResponse {
    pub body: Option<RpcBlockBody>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTransactionKernelRequest {
    pub selector: BlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTransactionKernelResponse {
    pub kernel: Option<RpcTransactionKernel>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockAnnouncementsRequest {
    pub selector: BlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockAnnouncementsResponse {
    pub announcements: Option<Vec<RpcAnnouncement>>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct IsBlockCanonicalRequest {
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsBlockCanonicalResponse {
    pub canonical: bool,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetUtxoDigestRequest {
    pub leaf_index: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetUtxoDigestResponse {
    pub digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct AreBloomIndicesSetRequest {
    pub absolute_index_set: RpcAbsoluteIndexSet,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AreBloomIndicesSetResponse {
    pub are_set: bool,
}

/* Wallet */

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlocksRequest {
    pub from_height: RpcBlockHeight,
    pub to_height: RpcBlockHeight,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlocksResponse {
    pub blocks: Vec<RpcWalletBlock>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct RestoreMembershipProofRequest {
    pub absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreMembershipProofResponse {
    pub snapshot: RpcMsMembershipSnapshot,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct SubmitTransactionRequest {
    pub transaction: RpcTransaction,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitTransactionResponse {
    pub success: bool,
}

/* Mining */

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct SubmitBlockTemplateRequest {
    pub block: RpcBlock,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitBlockTemplateResponse {
    pub success: bool,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTemplateRequest {
    pub guesser_address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTemplateResponse {
    pub template: Option<RpcBlockTemplate>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct SubmitBlockRequest {
    pub template: RpcBlock,
    pub pow: RpcBlockPow,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitBlockResponse {
    pub success: bool,
}

/* Mempool */

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsResponse {
    pub transactions: Vec<RpcTransactionKernelId>,
    pub metadata: RpcMempoolMetadata,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionRequest {
    pub id: RpcTransactionKernelId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionResponse {
    pub transaction: Option<RpcTransaction>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionKernelRequest {
    pub id: RpcTransactionKernelId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionKernelResponse {
    pub kernel: Option<RpcTransactionKernel>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionProofRequest {
    pub id: RpcTransactionKernelId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionProofResponse {
    pub proof: Option<RpcTransactionProof>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionsByAdditionRecordsRequest {
    pub addition_records: Vec<RpcAdditionRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionsByAdditionRecordsResponse {
    pub transactions: Vec<TransactionKernelWithPriority>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionsByAbsoluteIndexSetsRequest {
    pub absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionsByAbsoluteIndexSetsResponse {
    pub transactions: Vec<TransactionKernelWithPriority>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct BestTransactionForNextBlockRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BestTransactionForNextBlockResponse {
    pub transaction: Option<RpcTransactionKernel>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct BanRequest {
    pub address: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BanResponse {}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct UnbanRequest {
    pub address: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbanResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct UnbanAllRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbanAllResponse {}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct DialRequest {
    pub address: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct ProbeNatRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeNatResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct ResetRelayReservationsRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetRelayReservationsResponse {}
