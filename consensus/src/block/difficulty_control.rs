use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::Add;
use std::ops::Shr;
use std::ops::ShrAssign;

use anyhow::ensure;

use get_size2::GetSize;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use num_traits::Zero;
use rand::Rng;
use rand::RngExt;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::Digest;

use super::block_height::BlockHeight;
use crate::proof_abstractions::timestamp::Timestamp;

const DIFFICULTY_NUM_LIMBS: usize = 5;

/// Estimated number of hashes required to find a block.
///
/// Every `Difficulty` determines a *target*, which is a hash digest. A block
/// has proof-of-work if its hash is smaller than the difficulty of its
/// predecessor.
///
/// The `Difficulty` is set by the `difficulty_control` mechanism such that the
/// target block interval is by actual block times.
#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject, GetSize,
)]
pub struct Difficulty([u32; DIFFICULTY_NUM_LIMBS]);

impl Difficulty {
    pub const NUM_LIMBS: usize = DIFFICULTY_NUM_LIMBS;
    const LIMBS_FOR_MINIMUM: [u32; Self::NUM_LIMBS] = [6000, 0, 0, 0, 0];
    pub const MINIMUM: Self = Self::new(Self::LIMBS_FOR_MINIMUM);
    pub const MAXIMUM: Self = Self::new([u32::MAX; Self::NUM_LIMBS]);

    pub const fn new(difficulty: [u32; DIFFICULTY_NUM_LIMBS]) -> Self {
        let mut lte_minimum = true;
        let mut i = 0;
        while i < Self::NUM_LIMBS {
            if difficulty[i] > Self::LIMBS_FOR_MINIMUM[i] {
                lte_minimum = false;
            }
            i += 1;
        }
        if lte_minimum {
            Self(Self::LIMBS_FOR_MINIMUM)
        } else {
            Self(difficulty)
        }
    }

    /// Convert a difficulty to a target threshold so as to test a block's
    /// proof-of-work.
    pub fn target(&self) -> Digest {
        let difficulty_as_bui: BigUint = BigUint::from(*self);
        let max_threshold_as_bui: BigUint =
            Digest([BFieldElement::new(BFieldElement::MAX); Digest::LEN]).into();
        let threshold_as_bui: BigUint = max_threshold_as_bui / difficulty_as_bui;

        threshold_as_bui.try_into().unwrap()
    }

    /// Multiply the `Difficulty` with a positive fixed point rational number
    /// consisting of two u32s as limbs separated by the point. Returns the
    /// (wrapping) result and the out-of-bounds limb containing the overflow, if
    /// any.
    fn safe_mul_fixed_point_rational(&self, lo: u32, hi: u32) -> (Self, u32) {
        let mut new_difficulty = [0; Self::NUM_LIMBS + 1];
        let mut carry = 0;
        for (old_difficulty_i, new_difficulty_i) in self
            .0
            .iter()
            .zip(new_difficulty.iter_mut().take(Self::NUM_LIMBS))
        {
            let sum = u64::from(carry) + u64::from(*old_difficulty_i) * u64::from(lo);
            *new_difficulty_i = sum as u32;
            carry = (sum >> 32) as u32;
        }
        new_difficulty[Self::NUM_LIMBS] = carry;
        carry = 0;
        for (old_difficulty_i, new_difficulty_i_plus_one) in
            self.0.iter().zip(new_difficulty.iter_mut().skip(1))
        {
            let sum = u64::from(carry) + u64::from(*old_difficulty_i) * u64::from(hi);
            let (digit, carry_bit) = new_difficulty_i_plus_one.overflowing_add(sum as u32);
            *new_difficulty_i_plus_one = digit;
            carry = ((sum >> 32) as u32) + u32::from(carry_bit);
        }

        (
            Difficulty::new(new_difficulty[1..].to_owned().try_into().unwrap()),
            carry,
        )
    }

    /// Converts a BigUint into Difficulty. Returns None if it doesn’t fit.
    pub fn from_biguint(big: BigUint) -> Option<Self> {
        if big.iter_u32_digits().count() > Self::NUM_LIMBS {
            return None;
        }

        Some(Self(
            big.iter_u32_digits()
                .take(Self::NUM_LIMBS)
                .pad_using(Self::NUM_LIMBS, |_| 0u32)
                .collect_vec()
                .try_into()
                .unwrap(),
        ))
    }
}

impl IntoIterator for Difficulty {
    type Item = u32;
    type IntoIter = std::array::IntoIter<Self::Item, { Self::NUM_LIMBS }>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<Difficulty> for BigUint {
    fn from(value: Difficulty) -> Self {
        let mut bi = BigUint::zero();
        for &limb in value.0.iter().rev() {
            bi = (bi << 32) + limb;
        }
        bi
    }
}

impl PartialOrd for Difficulty {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Difficulty {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .into_iter()
            .rev()
            .zip(other.0.into_iter().rev())
            .map(|(lhs, rhs)| lhs.cmp(&rhs))
            .fold(Ordering::Equal, |acc, new| match acc {
                Ordering::Less => acc,
                Ordering::Equal => new,
                Ordering::Greater => acc,
            })
    }
}

impl Shr<usize> for Difficulty {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        let limb_offset = rhs / 32;
        let mut array = self
            .0
            .into_iter()
            .skip(limb_offset)
            .pad_using(Self::NUM_LIMBS, |_| 0u32)
            .collect_vec();

        let remainder = rhs % 32;
        if remainder.is_zero() {
            return Difficulty::new(array.try_into().unwrap());
        }

        let mut borrow = 0u32;
        for i in (0..Self::NUM_LIMBS).rev() {
            let new_borrow = array[i] & ((1 << remainder) - 1);
            array[i] = (array[i] >> remainder) | (borrow << (32 - remainder));
            borrow = new_borrow;
        }

        Difficulty::new(array.try_into().unwrap())
    }
}

impl ShrAssign<usize> for Difficulty {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}

impl Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BigUint::from(*self))
    }
}

impl<T> From<T> for Difficulty
where
    T: Into<u32>,
{
    fn from(value: T) -> Self {
        let mut array = [0u32; Self::NUM_LIMBS];
        array[0] = value.into();
        Self(array)
    }
}

impl Distribution<Difficulty> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Difficulty {
        let inner = rng.random();
        Difficulty(inner)
    }
}

const POW_NUM_LIMBS: usize = 6;

/// Estimates how many guesses (or guess-equivalents, in case of time-memory
/// trade-offs) were used to produce the block.
///
/// Proof-of-work is used in the fork choice rule: when presented with
/// two forks of different height, a node will choose the one with the greater
/// amount of proof-of-work.
#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject, GetSize,
)]
pub struct ProofOfWork([u32; POW_NUM_LIMBS]);

impl ProofOfWork {
    pub const MAXIMUM: Self = ProofOfWork([u32::MAX; POW_NUM_LIMBS]);
    pub const MINIMUM: Self = ProofOfWork([0u32; POW_NUM_LIMBS]);
    pub const NUM_LIMBS: usize = POW_NUM_LIMBS;
    pub const fn new(amount: [u32; Self::NUM_LIMBS]) -> Self {
        Self(amount)
    }
}

impl IntoIterator for ProofOfWork {
    type Item = u32;
    type IntoIter = std::array::IntoIter<Self::Item, { Self::NUM_LIMBS }>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> Add<T> for ProofOfWork
where
    T: IntoIterator<Item = u32>,
{
    type Output = ProofOfWork;

    fn add(self, rhs: T) -> Self::Output {
        let mut result = [0; Self::NUM_LIMBS];
        let mut carry = 0;
        let mut n = 0;
        for (i, (difficulty_digit, pow_digit)) in rhs.into_iter().zip(self.0).enumerate() {
            let sum = u64::from(carry) + u64::from(difficulty_digit) + u64::from(pow_digit);
            result[i] = sum as u32;
            carry = (sum >> 32) as u32;
            n += 1;
        }
        for (self_i, result_i) in self.into_iter().zip(result.iter_mut()).skip(n) {
            let sum = u64::from(carry) + u64::from(self_i);
            *result_i = sum as u32;
            carry = (sum >> 32) as u32;
        }
        Self(result)
    }
}

impl Zero for ProofOfWork {
    fn zero() -> Self {
        Self::new([0u32; Self::NUM_LIMBS])
    }

    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

impl From<ProofOfWork> for BigUint {
    fn from(value: ProofOfWork) -> Self {
        let mut bi = BigUint::zero();
        for &limb in value.0.iter().rev() {
            bi = (bi << 32) + limb;
        }
        bi
    }
}

impl TryFrom<BigUint> for ProofOfWork {
    type Error = anyhow::Error;

    fn try_from(big: BigUint) -> Result<Self, Self::Error> {
        ensure!(
            !big.iter_u32_digits().count() > Self::NUM_LIMBS,
            "exceeds maximum ProofOfWork value"
        );

        Ok(Self(
            big.iter_u32_digits()
                .take(Self::NUM_LIMBS)
                .pad_using(Self::NUM_LIMBS, |_| 0u32)
                .collect_vec()
                .try_into()
                .unwrap(),
        ))
    }
}

impl TryFrom<f64> for ProofOfWork {
    type Error = anyhow::Error;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        ensure!(!value.is_nan(), "cannot convert NaN to ProofOfWork value");

        if value < 0_f64 {
            return Ok(ProofOfWork::MINIMUM);
        }
        if value.is_infinite() {
            return Ok(ProofOfWork::MAXIMUM);
        }
        let digits = BigUint::from_f64(value).unwrap().to_u32_digits();
        if digits.len() > POW_NUM_LIMBS && digits.iter().skip(POW_NUM_LIMBS).any(|&d| d != 0) {
            return Ok(ProofOfWork::MAXIMUM);
        }
        Ok(ProofOfWork(
            digits
                .into_iter()
                .pad_using(POW_NUM_LIMBS, |_| 0u32)
                .take(POW_NUM_LIMBS)
                .collect_vec()
                .try_into()
                .unwrap(),
        ))
    }
}

impl PartialOrd for ProofOfWork {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProofOfWork {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .into_iter()
            .rev()
            .zip(other.0.into_iter().rev())
            .map(|(lhs, rhs)| lhs.cmp(&rhs))
            .fold(Ordering::Equal, |acc, new| match acc {
                Ordering::Less => acc,
                Ordering::Equal => new,
                Ordering::Greater => acc,
            })
    }
}

impl Display for ProofOfWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BigUint::from(*self))
    }
}

impl Distribution<ProofOfWork> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ProofOfWork {
        let inner = rng.random();
        ProofOfWork(inner)
    }
}

/// Control system for block difficulty.
///
/// This function computes the new block's difficulty from the block's
/// timestamp, the previous block's difficulty, and the previous block's
/// timestamp. It regulates the block interval by tuning the difficulty.
/// It assumes that the block timestamp is valid.
///
/// This mechanism is a PID controller with P = -2^-4 (and I = D = 0) and with
/// with a few modifications such as clamping multiplicative instead of
/// additive correction.
///
/// The following diagram describes the mechanism.
///
/// ```notest
///                             --------------
///                            |              |------ new timestamp ------
///  --- new difficulty    --->|  blockchain  |------ old timestamp ----  |
/// |   (control signal)       |              |------ old difficulty -  | |
/// |                           --------------                        | | |
/// |   ---                                                           | | |
///  --| * |<---------------------------------------------------------  | |
///     ---                                                             | |
///      ^ PID                                                          | |
///      | adjustment                                                 - v v
///      |                                                              ---
///      |                                                             | + |
///     ---                                                             ---
///    | + |<--- 1.0                                          (process   |
///     ---                                    (setpoint:)    variable:) |
///      ^                                       target         observed |
///      |                                        block       block time |
///      |                                       interval                v
///      |                                         |                 -  ---
///      |                                         |------------------>| + |
///      |                                         |                    ---
///      |                                         |                     |
///      |                                         v                     |
///      |   (P =)                               -----                   |
///      |   -2^-4                              | 1/x |                  |
///      |     |                                 -----                   |
///      |     v                                   v                     |
///      |    ---     ---------------             ---     absolute error |
///       ---| * |<--| clamp [-1; 4] |<----------| * |<------------------
///           ---     ---------------   relative  ---
///                                      error
///``
/// The P-controller (without clamping) does have a systematic error up to -5%
/// of the setpoint, whose exact magnitude depends on the relation between
/// proving and guessing time. This bias could be eliminated in principle by
/// setting I and D; but the resulting controller is more complex (=> difficult
/// to implement), generates overshoot (=> bad for liveness), and periodicity
/// (=> attack vector). Most importantly, the bias is counteracted to some
/// degree by the clamping.
/// ```
pub fn difficulty_control(
    new_timestamp: Timestamp,
    old_timestamp: Timestamp,
    old_difficulty: Difficulty,
    target_block_interval: Timestamp,
    previous_block_height: BlockHeight,
) -> Difficulty {
    // no adjustment if the previous block is the genesis block
    if previous_block_height.is_genesis() {
        return old_difficulty;
    }

    // otherwise, compute PID control signal

    // most recent observed block time
    let delta_t = new_timestamp - old_timestamp;

    // distance to target
    let absolute_error = (delta_t.0.value() as i64) - (target_block_interval.0.value() as i64);
    let relative_error =
        i128::from(absolute_error) * ((1 << 32) / i128::from(target_block_interval.0.value()));
    let clamped_error = relative_error.clamp(-1 << 32, 4 << 32);

    // Errors smaller than -1 cannot occur because delta_t >= MINIMUM_BLOCK_TIME > 0.
    // Errors greater than 4 can occur but are clamped away because otherwise a
    // single arbitrarily large concrete block time can induce an arbitrarily
    // large downward adjustment to the difficulty.
    // After clamping a `u64` suffices but before clamping we might get overflow
    // for very large block times so we use i128 for the `relative_error`.

    // change to control signal
    // adjustment_factor = (1 + P * error)
    // const P: f64 = -1.0 / 16.0;
    let one_plus_p_times_error = (1 << 32) + ((-clamped_error) >> 4);
    debug_assert!(one_plus_p_times_error.is_positive());

    let lo = one_plus_p_times_error as u32;
    let hi = (one_plus_p_times_error >> 32) as u32;
    let (new_difficulty, overflow) = old_difficulty.safe_mul_fixed_point_rational(lo, hi);

    if overflow > 0 {
        Difficulty::MAXIMUM
    } else {
        new_difficulty
    }
}

/// Determine an upper bound for the maximum possible cumulative proof-of-work
/// after n blocks given the start conditions.
///
/// todo: this should accept target_block_interval and minimum_block_time params.
pub fn max_cumulative_pow_after(
    cumulative_pow_start: ProofOfWork,
    difficulty_start: Difficulty,
    num_blocks: usize,
    target_block_interval: Timestamp,
    minimum_block_time: Timestamp,
) -> ProofOfWork {
    // If the observed interval between consecutive blocks is the minimum
    // allowed by the consensus rules, the clamped relative error is almost -1.
    // In this case the PID adjustment factor is
    // f =  1 + (MINIMUM_BLOCK_TIME - TARGET_BLOCK_INTERVAL) / TARGET_BLOCK_INTERVAL * P
    //   =  1 - (60 - 294) / 294 / 16,
    const EPSILON: f64 = 0.000001;
    let f = 1.0_f64
        + (target_block_interval.to_millis() - minimum_block_time.to_millis()) as f64
            / target_block_interval.to_millis() as f64
            / 16.0
        + EPSILON;
    let mut max_difficulty: f64 = BigUint::from(difficulty_start).to_f64().unwrap();
    let mut max_cumpow: f64 =
        BigUint::from(cumulative_pow_start).to_f64().unwrap() * (1.0 + EPSILON);
    let cap = BigUint::from(ProofOfWork::MAXIMUM).to_f64().unwrap();
    for _ in 0..num_blocks {
        max_difficulty *= f;
        max_cumpow += max_difficulty;

        // Avoid spending more time in loop if we've already reached max.
        if max_cumpow >= cap {
            return ProofOfWork::MAXIMUM;
        }
    }

    // This conversion is safe and cannot panic.
    ProofOfWork::try_from(max_cumpow).unwrap_or_else(|_e| {
        panic!("max_cumpow is within bounds where successful conversion should be guaranteed")
    })
}
