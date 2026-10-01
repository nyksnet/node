use std::fmt::Display;

use get_size2::GetSize;
use itertools::Itertools;
use rand::RngExt;
use rand::rngs::StdRng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::utxo::Utxo;

/// A list of UTXOs with an associated salt.
///
/// `SaltedUtxos` is a struct for representing a list of UTXOs in a witness object when it
/// is desirable to associate a random but consistent salt for the entire list of UTXOs.
/// This situation arises when two distinct consensus programs prove different features
/// about the same list of UTXOs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, GetSize, BFieldCodec, TasmObject)]
pub struct SaltedUtxos {
    pub utxos: Vec<Utxo>,
    pub salt: [BFieldElement; 3],
}

impl Display for SaltedUtxos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.utxos
                .iter()
                .enumerate()
                .map(|(i, utxo)| format!("\nutxo {i}: {utxo}"))
                .join("")
        )
    }
}

impl SaltedUtxos {
    /// Takes a Vec of UTXOs and returns a `SaltedUtxos` object. The salt comes from
    /// `thread_rng`.
    pub fn new(utxos: Vec<Utxo>) -> Self {
        Self {
            utxos,
            salt: rand::rng().random(),
        }
    }

    pub fn new_with_rng(utxos: Vec<Utxo>, rng: &mut StdRng) -> Self {
        Self {
            utxos,
            salt: rng.random(),
        }
    }

    /// Generate a `SaltedUtxos` object that contains no UTXOs. There is a random salt
    /// though, which comes from `thread_rng`.
    pub fn empty() -> Self {
        Self {
            utxos: vec![],
            salt: rand::rng().random(),
        }
    }

    /// Concatenate two `SaltedUtxos` objects. Derives the salt from hashing the
    /// concatenation of that of the operands.
    pub fn cat(&self, other: SaltedUtxos) -> Self {
        Self {
            utxos: [self.utxos.clone(), other.utxos].concat(),
            salt: Tip5::hash_varlen(&[self.salt, other.salt].concat().to_vec()).values()[0..3]
                .try_into()
                .unwrap(),
        }
    }
}

impl IntoIterator for SaltedUtxos {
    type Item = Utxo;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.utxos.into_iter()
    }
}
