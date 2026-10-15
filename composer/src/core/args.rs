use clap::Parser;
use num_traits::CheckedSub;
use num_traits::Zero;
use nyks_consensus::BFieldElement;
use nyks_consensus::block::MINING_REWARD_TIME_LOCK_PERIOD;
use nyks_consensus::network::Network;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_consensus::transaction::announcement::Announcement;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::address::Recipient;
use nyks_standards::wallet::notes::content::MessageContent;
use nyks_standards::wallet::notes::note::Note;
use nyks_standards::wallet::notes::note::PublicNote;
use nyks_wallet_core::transaction::builder::output::TxOutput;
use nyks_wallet_core::transaction::builder::output::TxOutputList;
use nyks_wallet_core::transaction::utxo::notifications::UtxoNotificationMedium;

use crate::core::coinbase_distribution::CoinbaseDistribution;

#[derive(Parser, Debug, Clone)]
#[command(name = "nyks-prover")]
#[command(about = "A nyks block prover")]
pub struct Args {
    /// RPC URL to use.
    #[arg(long, default_value = "http://localhost:9797")]
    pub rpc_url: String,

    /// Recipient of the coinbase rewards.
    #[arg(long)]
    pub address: String,

    /// Network we are generating templates on.
    #[arg(long, default_value_t = Network::Main)]
    pub network: Network,

    /// How much reward we leave for guessers.
    #[arg(long, default_value_t = 0.5f64)]
    pub guesser_fee_fraction: f64,

    /// Graffiti message to publish in the block announcement.
    #[arg(long, default_value = "nyks-composer")]
    pub graffiti: Option<String>,
}

impl Args {
    /// Produce outputs spending a given portion of the coinbase amount,
    /// according to the specified coinbase distribution.
    ///
    /// The coinbase amount is usually set to the block subsidy for this block
    /// height.
    ///
    /// Will always produce outputs where at least half the amount is timelocked
    /// for 3 years, since this is dictated by the consensus rules. The portion
    /// of the entire block subsidy that goes to the composer is determined by
    /// the `guesser_fee_fraction` field of the composer parameters.
    ///
    /// The sum of the value of the outputs is guaranteed to not exceed the
    /// coinbase amount, since the guesser fee fraction is guaranteed to be in the
    /// range \[0;1\].
    ///
    /// Returns: Either the empty list, or n outputs according to the specified
    /// coinbase distribution.
    ///
    /// # Panics
    ///
    /// If the provided guesser fee fraction is not between 0 and 1 (inclusive).
    pub(crate) fn tx_outputs(
        &self,
        sender_randomness: Digest,
        coinbase_amount: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> TxOutputList {
        let guesser_fee = coinbase_amount.lossy_f64_fraction_mul(self.guesser_fee_fraction);

        let total_composer_amount = coinbase_amount
            .checked_sub(&guesser_fee)
            .expect("total_composer_fee cannot exceed coinbase_amount");

        if total_composer_amount.is_zero() {
            return Vec::<TxOutput>::default().into();
        }

        let notification_medium = UtxoNotificationMedium::OnChain; // cold mode by default and app doesnt support exporting notes so...
        let mut ret = vec![];
        let mut distributed = NativeCurrencyAmount::zero();
        let coinbase_distribution =
            CoinbaseDistribution::solo(Address::from_bech32m(&self.address, self.network).unwrap()); // TODO: support better distribution
        for coinbase_output in coinbase_distribution.iter() {
            let amount = total_composer_amount
                .scalar_mul(coinbase_output.fraction_in_promille())
                .to_nau()
                / 1000i128;
            let amount = NativeCurrencyAmount::from_nau(amount);
            distributed += amount;
            let mut tx_output = TxOutput::native_currency(
                amount,
                sender_randomness,
                coinbase_output.recipient().to_owned(),
                notification_medium,
            );

            if coinbase_output.is_timelocked() {
                let small_delta = Timestamp::minutes(30);
                let release_date = timestamp + MINING_REWARD_TIME_LOCK_PERIOD + small_delta;
                tx_output = tx_output.with_time_lock(release_date);
            }

            ret.push(tx_output);
        }

        // Correct any rounding errors that may have resulted from the use
        // of fractions. Do so in a consensus-compatible way guaranteeing that
        // the timelocked amount is greater than or equal to liquid amount.
        if distributed < total_composer_amount {
            // Add correction to timelocked output
            let correction = total_composer_amount.checked_sub(&distributed).unwrap();
            let first_liquid = ret
                .iter_mut()
                .find(|x| !x.is_timelocked())
                .expect("Must have at least one liquid output");
            *first_liquid = first_liquid.clone().add_to_amount(correction);
        } else {
            // Subtract correction from liquid output
            let correction = distributed.checked_sub(&total_composer_amount).unwrap();
            let first_liquid = ret
                .iter_mut()
                .find(|x| !x.is_timelocked())
                .expect("Must have at least one liquid output");
            *first_liquid = first_liquid.clone().add_to_amount(-correction);
        };

        ret.into()
    }

    pub(crate) fn announcement(&self) -> Option<Announcement> {
        self.graffiti.as_ref().map(|message| {
            let message = format!("{message} {}", env!("CARGO_PKG_VERSION"));
            let content = MessageContent::without_random_suffix(message);
            let public_note = PublicNote::new(BFieldElement::new(0), content.into());

            Announcement::from(&Note::from(public_note))
        })
    }
}
