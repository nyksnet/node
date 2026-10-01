use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use nyks_consensus::BFieldElement;
use nyks_consensus::block::block_header::BlockPow;
use nyks_consensus::block::pow::GuesserBuffer;
use nyks_consensus::block::pow::POW_MEMORY_TREE_HEIGHT;
use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_consensus::tasm_lib::twenty_first::bfe_array;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;
use nyks_rpc_client::mining::template::RpcBlockTemplate;
use rand::RngExt;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::info;
use tracing::warn;

// ~10 GB, shared via Arc rather than cloned per task.
#[derive(Debug)]
struct MinerBuffer {
    digest: Digest,
    buffer: Arc<GuesserBuffer<POW_MEMORY_TREE_HEIGHT>>,
}

// Holds the cancel flag so stop() can signal the blocking thread directly.
#[derive(Debug)]
struct MinerTask {
    template: Arc<RpcBlockTemplate>,
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

#[derive(Clone, Debug)]
pub struct Guesser {
    client: HttpClient,
    buffer: Arc<RwLock<Option<MinerBuffer>>>,
    task: Arc<RwLock<Option<MinerTask>>>,
}

impl Guesser {
    pub fn new(client: HttpClient) -> Self {
        Guesser {
            client,
            buffer: Arc::new(RwLock::new(None)),
            task: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn is_running(&self) -> bool {
        self.task.read().await.is_some()
    }

    pub async fn override_task(&self, prev_block_digest: Digest, template: RpcBlockTemplate) {
        self.stop().await;

        let guesser_buffer = self.get_or_recompute_buffer(prev_block_digest).await;
        let template = Arc::new(template);

        info!(
            "Switching to mining template {}...",
            template.block.kernel.mast_hash().to_hex()
        );

        let cancel = Arc::new(AtomicBool::new(false));

        let client = self.client.clone();
        let task_template = template.clone();
        let task_cancel = cancel.clone();

        let handle = tokio::spawn(async move {
            Self::run_mining_task(client, task_template, guesser_buffer, task_cancel).await;
        });

        *self.task.write().await = Some(MinerTask {
            template,
            cancel,
            handle,
        });
    }

    // Only recomputes when the chain tip changes.
    async fn get_or_recompute_buffer(
        &self,
        prev_block_digest: Digest,
    ) -> Arc<GuesserBuffer<POW_MEMORY_TREE_HEIGHT>> {
        let mut guard = self.buffer.write().await;

        let needs_recompute = guard
            .as_ref()
            .map(|b| b.digest != prev_block_digest)
            .unwrap_or(true);
        if needs_recompute {
            info!(
                "Computing guesser buffer for digest {}...",
                prev_block_digest.to_hex()
            );

            let new_buffer = Arc::new(BlockPow::preprocess(prev_block_digest));

            *guard = Some(MinerBuffer {
                digest: prev_block_digest,
                buffer: new_buffer.clone(),
            });
            new_buffer
        } else {
            guard.as_ref().unwrap().buffer.clone()
        }
    }

    pub async fn stop(&self) {
        let mut guard = self.task.write().await;

        if let Some(task) = guard.take() {
            info!(
                "Stopping mining task for template {:x}...",
                task.template.block.kernel.mast_hash()
            );
            task.cancel.store(true, Ordering::Relaxed);
            let _ = task.handle.await;
        }
    }

    async fn run_mining_task(
        client: HttpClient,
        template: Arc<RpcBlockTemplate>,
        guesser_buffer: Arc<GuesserBuffer<POW_MEMORY_TREE_HEIGHT>>,
        cancel: Arc<AtomicBool>,
    ) {
        let hashes_done = Arc::new(AtomicU64::new(0));
        let logger_handle = Self::spawn_hashrate_logger(hashes_done.clone(), cancel.clone());

        loop {
            if cancel.load(Ordering::Relaxed) {
                break;
            }

            let mining_template = template.clone();
            let guesser_buffer_for_mine = guesser_buffer.clone();
            let cancel_for_mine = cancel.clone();
            let hashes_done_for_mine = hashes_done.clone();

            let mine_result = tokio::task::spawn_blocking(move || {
                mine(
                    &mining_template,
                    &guesser_buffer_for_mine,
                    &cancel_for_mine,
                    &hashes_done_for_mine,
                )
            })
            .await;

            let pow = match mine_result {
                Ok(Some(pow)) => pow,
                Ok(None) => {
                    info!("Mining stopped (cancelled or nonce space exhausted).");
                    break;
                }
                Err(e) => {
                    info!("Mining task panicked: {e}");
                    break;
                }
            };

            info!("Found the solution! Submitting to node...");

            match client
                .submit_block(template.block.clone(), pow.into())
                .await
            {
                Ok(response) if response.success => {
                    info!("Block is accepted by node.");
                    break;
                }
                Ok(_) => warn!("Block is rejected by node, channel error. Retrying..."),
                Err(e) => warn!("Block is rejected by node, reason: {}. Retrying...", e),
            }
        }

        logger_handle.abort();
    }

    fn spawn_hashrate_logger(
        hashes_done: Arc<AtomicU64>,
        cancel: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            let start = Instant::now();
            interval.tick().await;

            while !cancel.load(Ordering::Relaxed) {
                interval.tick().await;
                let total = hashes_done.load(Ordering::Relaxed);
                let rate = total as f64 / start.elapsed().as_secs_f64().max(0.001);
                info!("Hashrate: {:.2} MH/s ({total} total)", rate / 1e6);
            }
        })
    }
}

// Parallel nonce search. Returns None if cancelled or exhausted.
fn mine(
    template: &RpcBlockTemplate,
    guesser_buffer: &GuesserBuffer<POW_MEMORY_TREE_HEIGHT>,
    cancel: &AtomicBool,
    hashes_done: &AtomicU64,
) -> Option<BlockPow> {
    // Check for cancellation every ~500k nonces rather than every iteration.
    const CHECKPOINT_DISTANCE: u64 = 1 << 19;

    let index_picker_preimage =
        guesser_buffer.index_picker_preimage(&template.metadata.pow_mast_paths);

    // Each mining run gets its own random 256‑bit prefix on nonce space.
    let mut rng = rand::rng();
    let n0: u64 = rng.random();
    let n1: u64 = rng.random();
    let n2: u64 = rng.random();
    let n3: u64 = rng.random();

    info!(
        "Mining with nonce prefix [{:#018x}, {:#018x}, {:#018x}, {:#018x}]",
        n0, n1, n2, n3
    );

    (0u64..u64::MAX)
        .into_par_iter()
        .find_map_any(|i| {
            if i % CHECKPOINT_DISTANCE == 0 {
                hashes_done.fetch_add(CHECKPOINT_DISTANCE, Ordering::Relaxed);
                if cancel.load(Ordering::Relaxed) {
                    return Some(None);
                }
            }

            let nonce = Digest(bfe_array![n0, n1, n2, n3, i]);

            BlockPow::guess(
                guesser_buffer,
                &template.metadata.pow_mast_paths,
                index_picker_preimage,
                nonce,
                template.metadata.threshold,
            )
            .map(Some)
        })
        .flatten()
}
