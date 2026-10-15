use anyhow::Result;
use anyhow::ensure;
use nyks_consensus::BFieldElement;
use nyks_consensus::network::Network;
use nyks_consensus::twenty_first::tip5::Tip5;
use sha3::Shake256;
use sha3::digest::ExtendableOutput;
use sha3::digest::Update;

use crate::wallet::notes::content::NoteContent;

pub mod address;
pub mod key;
pub mod schemes;
pub mod viewing_key;

/// returns human-readable-prefix for the given network
pub(crate) fn network_hrp_char(network: Network) -> char {
    match network {
        Network::Main => 'm',
        Network::Testnet(_) => 't',
        Network::TestnetMock => 'z',
        Network::RegTest => 'r',
    }
}

/// Derive a seed and nonce deterministically from note content so encrypting
/// the same content again produces the same announcement. These values are
/// used in the encryption step and allow proofs to be reused in tests.
pub(crate) fn deterministically_derive_seed_and_nonce(
    content: &NoteContent,
) -> ([u8; 32], BFieldElement) {
    match content {
        NoteContent::Utxo(u) => {
            let combined = Tip5::hash_pair(u.sender_randomness, Tip5::hash(&u.utxo));
            let [e0, e1, e2, e3, e4] = combined.values();
            let e0: [u8; 8] = e0.into();
            let e1: [u8; 8] = e1.into();
            let e2: [u8; 8] = e2.into();
            let e3: [u8; 8] = e3.into();
            let seed: [u8; 32] = [e0, e1, e2, e3].concat().try_into().unwrap();

            (seed, e4)
        }
        NoteContent::Message(m) => {
            let hash = Tip5::hash(&m.message);
            let [e0, e1, e2, e3, e4] = hash.values();
            let e0: [u8; 8] = e0.into();
            let e1: [u8; 8] = e1.into();
            let e2: [u8; 8] = e2.into();
            let e3: [u8; 8] = e3.into();
            let seed = [e0, e1, e2, e3].concat().try_into().unwrap();

            (seed, e4)
        }
    }
}

// note: copied from twenty_first::math::lattice::kem::shake256()
//       which is not public
pub(crate) fn shake256<const NUM_OUT_BYTES: usize>(
    randomness: impl AsRef<[u8]>,
) -> [u8; NUM_OUT_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(randomness.as_ref());

    let mut result = [0u8; NUM_OUT_BYTES];
    hasher.finalize_xof_into(&mut result);
    result
}

/// Encodes a slice of bytes to a vec of BFieldElements. This
/// encoding is injective but not uniform-to-uniform.
pub(crate) fn bytes_to_bfes_packed(bytes: &[u8]) -> Vec<BFieldElement> {
    let mut padded_bytes = bytes.to_vec();
    while !padded_bytes.len().is_multiple_of(8) {
        padded_bytes.push(0u8);
    }
    let mut bfes = vec![BFieldElement::new(bytes.len() as u64)];
    for chunk in padded_bytes.chunks(8) {
        let ch: [u8; 8] = chunk.try_into().unwrap();
        let int = u64::from_be_bytes(ch);
        if int < BFieldElement::P - 1 {
            bfes.push(BFieldElement::new(int));
        } else {
            let rem = int & 0xffffffff;
            bfes.push(BFieldElement::new(BFieldElement::P - 1));
            bfes.push(BFieldElement::new(rem));
        }
    }
    bfes
}

/// Decodes a slice of BFieldElements to a vec of bytes. This method
/// computes the inverse of `bytes_to_bfes`.
///
/// Fails if the number of bytes exceed 8*10^6.
pub fn bfes_to_bytes_packed(bfes: &[BFieldElement]) -> Result<Vec<u8>> {
    const MAX_DECODED_LENGTH: usize = BFieldElement::BYTES * 1_000_000;
    ensure!(!bfes.is_empty(), "Cannot decode empty byte stream");

    let claimed_length = bfes[0].value() as usize;
    ensure!(
        claimed_length <= size_of_val(bfes),
        "Cannot decode byte stream shorter than length indicated. \
        BFE slice length: {}, indicated byte stream length: {claimed_length}",
        bfes.len(),
    );

    ensure!(
        claimed_length <= MAX_DECODED_LENGTH,
        "Claimed length must not exceed {MAX_DECODED_LENGTH}"
    );

    let mut bytes: Vec<u8> = Vec::with_capacity(claimed_length);
    let mut skip_top = false;
    for bfe in bfes.iter().skip(1) {
        let bfe_bytes = bfe.value().to_be_bytes();
        if skip_top {
            bytes.append(&mut bfe_bytes[4..8].to_vec());
            skip_top = false;
        } else {
            bytes.append(&mut bfe_bytes[0..4].to_vec());
            if bfe_bytes[0..4] == [0xff, 0xff, 0xff, 0xff] {
                skip_top = true;
            } else {
                bytes.append(&mut bfe_bytes[4..8].to_vec());
            }
        }
    }

    ensure!(
        claimed_length <= bytes.len(),
        "Claimed length cannot exceed actual length when decoding bytes"
    );

    Ok(bytes[0..claimed_length].to_vec())
}
