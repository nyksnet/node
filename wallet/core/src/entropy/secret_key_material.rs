use bip39::Mnemonic;
use itertools::Itertools;
use num_traits::ConstZero;
use num_traits::Zero;
use nyks_consensus::BFieldElement;
use nyks_consensus::triton_vm::prelude::XFieldElement;
use nyks_consensus::twenty_first::prelude::Polynomial;
use nyks_consensus::twenty_first::xfe;
use rand::RngExt;
use rand::SeedableRng;
use rand::rng;
use rand::rngs::StdRng;
use thiserror::Error;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

/// Holds the secret seed of a wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKeyMaterial(pub(crate) XFieldElement);

impl Zeroize for SecretKeyMaterial {
    fn zeroize(&mut self) {
        self.0 = XFieldElement::zero();
    }
}

impl Drop for SecretKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKeyMaterial {}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum ShamirSecretSharingError {
    /// When t = 0 or t = 1, Shamir secret sharing is disallowed because (t=0)
    /// it is impossible or (t=1) all shares contain all of the information
    /// about the secret being shared, undermining the security benefits.
    #[error("quorum size t must be at least 2")]
    QuorumTooSmall,

    /// When t > n, Shamir secret sharing is disallowed because it would be
    /// impossible to reconstruct the original secret from *all* of the shares,
    /// let alone a smaller quorum.
    #[error("quorum t cannot exceed share count n")]
    ImpossibleRecombination,

    /// When n < 1, there are no shares to hand out, so Shamir secret sharing
    /// is disallowed.
    #[error("n must be at least 1")]
    NotEnoughSharesToSplit,

    /// Attempting to combine <t shares from a t-out-of-n Shamir secret sharing
    /// scheme will fail because the original sharing polynomial cannot uniquely
    /// be determined.
    #[error("need at least t shares to recombine")]
    TooFewSharesToRecombine,

    /// You should not be able to issue a share corresponding to the evaluation
    /// of the sharing polynomial at 0, as this share is identical to the
    /// original secret.
    #[error("share index 0 is reserved for the secret itself")]
    InvalidShare,

    /// When trying to reconstruct the original secret from a list of >=t
    /// shares, it is important to guarantee that all shares have distinct
    /// indices. Otherwise, there is either a duplicate share (both coordinates
    /// are the same) and redundant information is provided, or else there is
    /// a pair of inconsistent shares (having the same x-coordinate and
    /// different y-coordinates).
    #[error("duplicate share index in recombination input")]
    DuplicateIndex,

    /// When combining >t shares from a t-out-of-n Shamir secret sharing scheme,
    /// the reconstructed sharing polynomial should be of degree (at most) t.
    /// If this not the case, at least one of the shares is corrupt.
    #[error("reconstructed polynomial degree >= t; at least one share is corrupt")]
    InconsistentShares,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FromPhraseError {
    #[error("invalid BIP-39 phrase: {0}")]
    InvalidMnemonic(String),

    #[error("expected 24 bytes of entropy, got {0}")]
    UnexpectedEntropyLength(usize),
}

impl SecretKeyMaterial {
    /// Split the secret across n shares such that combining any t of them
    /// yields the secret again.
    ///
    /// A t-out-of-n Shamir secret sharing scheme defines a polynomial p(X) of
    /// degree at most t with uniformly random coefficients except the constant
    /// coefficient, which is equal to the secret S being shared, *i.e.*,
    /// p(0) = S . The shares are then (i, p(i)) for i in 1..=n.
    ///
    /// Upon combining t (or more) shares, one reproduces the original secret S
    /// by first interpolating the polynomial through the t points, and then by
    /// evaluating this polynomial in zero.
    ///
    /// This function is responsible for the splitting part.
    /// [`combine_shamir`](Self::combine_shamir) does the recombination.
    pub fn share_shamir(
        &self,
        t: usize,
        n: usize,
        seed: [u8; 32],
    ) -> Result<Vec<(usize, Self)>, ShamirSecretSharingError> {
        if n < 1 {
            return Err(ShamirSecretSharingError::NotEnoughSharesToSplit);
        }
        if t < 2 {
            return Err(ShamirSecretSharingError::QuorumTooSmall);
        }
        if t > n {
            return Err(ShamirSecretSharingError::ImpossibleRecombination);
        }
        let mut rng = StdRng::from_seed(seed);

        let polynomial_coefficients = (0..t)
            .map(|i| if i == 0 { self.0 } else { rng.random() })
            .collect_vec();

        let evaluation_indices = (1..=n).collect_vec();
        let evaluation_points = evaluation_indices.iter().map(|i| xfe!(*i)).collect_vec();
        let secret_shares =
            Polynomial::new(polynomial_coefficients).batch_evaluate(&evaluation_points);
        Ok(evaluation_indices
            .into_iter()
            .zip(secret_shares.into_iter().map(SecretKeyMaterial))
            .collect_vec())
    }

    /// Combine a quorum of Shamir secret shares into one.
    ///
    /// See [`share_shamir`](Self::share_shamir).
    pub fn combine_shamir(
        t: usize,
        shares: Vec<(usize, SecretKeyMaterial)>,
    ) -> Result<SecretKeyMaterial, ShamirSecretSharingError> {
        if shares.len() < t {
            return Err(ShamirSecretSharingError::TooFewSharesToRecombine);
        }

        let mut indices = shares.iter().map(|(i, _)| *i).collect_vec();

        let ordinates = indices.iter().map(|i| xfe!(*i)).collect_vec();
        indices.sort();
        indices.dedup();
        if indices.len() != ordinates.len() {
            return Err(ShamirSecretSharingError::DuplicateIndex);
        }
        if ordinates.contains(&XFieldElement::ZERO) {
            return Err(ShamirSecretSharingError::InvalidShare);
        }

        let abscissae = shares.into_iter().map(|(_, y)| y.0).collect_vec();
        let polynomial = Polynomial::interpolate(&ordinates, &abscissae);
        if polynomial.degree() > 0 && polynomial.degree() as usize >= t {
            return Err(ShamirSecretSharingError::InconsistentShares);
        }

        let p0 = polynomial.evaluate(XFieldElement::ZERO);
        Ok(SecretKeyMaterial(p0))
    }

    /// Generate fresh random secret key material using the operating system's
    /// cryptographically secure random number generator.
    pub fn random() -> Self {
        Self(rng().random())
    }

    /// Convert a seed phrase into [`SecretKeyMaterial`].
    pub fn from_phrase(phrase: &[String]) -> Result<Self, FromPhraseError> {
        let mnemonic = Mnemonic::from_phrase(&phrase.iter().join(" "), bip39::Language::English)
            .map_err(|e| FromPhraseError::InvalidMnemonic(e.to_string()))?;

        let entropy = mnemonic.entropy();
        let secret_seed: [u8; 24] = entropy
            .try_into()
            .map_err(|_| FromPhraseError::UnexpectedEntropyLength(entropy.len()))?;

        let xfe = XFieldElement::new(
            secret_seed
                .chunks(8)
                .map(|ch| u64::from_le_bytes(ch.try_into().unwrap()))
                .map(BFieldElement::new)
                .collect_vec()
                .try_into()
                .unwrap(),
        );
        Ok(Self(xfe))
    }

    /// Convert the secret key material into a BIP-39 phrase consisting of 18
    /// words (for 192 bits of entropy).
    pub fn to_phrase(&self) -> Vec<String> {
        let entropy: Vec<_> = self
            .0
            .coefficients
            .iter()
            .flat_map(|bfe| bfe.value().to_le_bytes())
            .collect();
        assert_eq!(
            entropy.len(),
            24,
            "Entropy for secret seed does not consist of 24 bytes."
        );
        let mnemonic = Mnemonic::from_entropy(&entropy, bip39::Language::English)
            .expect("Wrong entropy length (should be 24 bytes).");
        mnemonic
            .phrase()
            .split(' ')
            .map(|s| s.to_string())
            .collect_vec()
    }
}
