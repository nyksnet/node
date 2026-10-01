use std::collections::VecDeque;
use std::ops::BitOr;
use std::ops::Not;

use itertools::Itertools;
use rand::Rng;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Deserialize;
use serde::Serialize;

/// A [`SynchronizationBitMask`] is a representation of the synchronization
/// state of a set of indexed elements (such as blocks). It captures the state
/// of a system where all elements up to a certain bound can be enumerated in
/// principle, but some elements are present, and some are not.
///
/// [`SynchronizationBitMask`]s can be used to as a database to concisely
/// represent which blocks have been downloaded already and which have not, or
/// as a reconciliation primitive for syncing peers to rapidly determine which
/// blocks they can serve that their counterparts are missing.
//
// # Implementation Details
//
// Up to and including index `lower_bound`, all bits are implicitly set to 1.
// At and beyond index `upper_bound`, all bits are implicitly set to 0. Between
// the lower and upper bound, the bits can be 0 or 1, and so these bits are
// represented explicitly through a vector of u32s called `limbs`. The index
// boundary separating one limb from the next is independent of `lower_bound`
// and of `upper_bound`, but the values of these bounds can affect which slice
// of limbs is stored.
//
// Not every bit mask has a unique representation. Two SynchronizationBitMasks
// can be equivalent as bit masks but have a different upper bound.
//
// However, with respect to the lower bound, this value is guaranteed to be set
// to the highest possible value. So in particular, the bit at index
// `lower_bound` must always be 0. Whenever this bit is set to 1, the
// `lower_bound` increases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynchronizationBitMask {
    // inclusive
    pub lower_bound: u64,

    // exclusive
    pub upper_bound: u64,

    limbs: VecDeque<u32>,
}

impl PartialEq for SynchronizationBitMask {
    fn eq(&self, other: &Self) -> bool {
        if self.lower_bound != other.lower_bound || self.upper_bound != other.upper_bound {
            return false;
        }
        if self.lower_bound == self.upper_bound {
            return true;
        }
        if self.upper_bound.is_multiple_of(32) {
            return self.limbs == other.limbs;
        }
        let last = (self.upper_bound / 32) as usize;
        if last != 0
            && self
                .limbs
                .iter()
                .zip(other.limbs.iter())
                .take(last - 1)
                .any(|(l, r)| l != r)
        {
            return false;
        }
        let offset = (self.lower_bound / 32) as usize;
        let shamt = self.upper_bound % 32;
        let mask = (1u32 << shamt) - 1;
        (self.limbs[last - offset] ^ other.limbs[last - offset]) & mask == 0
    }
}
impl Eq for SynchronizationBitMask {}

impl Not for SynchronizationBitMask {
    type Output = SynchronizationBitMask;

    /// Inverts only the middle portion of the bit mask, not the all-ones at the
    /// start nor the infinite-zeros at the end.
    fn not(self) -> Self::Output {
        let mut limbs = self
            .limbs
            .iter()
            .map(|limb| !*limb)
            .collect::<VecDeque<u32>>();
        if let Some(limb) = limbs.back_mut() {
            let bound = self.upper_bound % 32;
            if bound != 0 {
                for i in bound..32 {
                    *limb &= !(1 << i);
                }
            }
        }
        SynchronizationBitMask {
            upper_bound: self.upper_bound,
            lower_bound: self.lower_bound,
            limbs,
        }
        .canonize()
    }
}

impl BitOr for SynchronizationBitMask {
    type Output = SynchronizationBitMask;

    fn bitor(self, rhs: Self) -> Self::Output {
        let upper_bound = u64::max(self.upper_bound, rhs.upper_bound);
        if upper_bound == 0 {
            return Self {
                lower_bound: 0,
                upper_bound,
                limbs: VecDeque::new(),
            };
        }

        let lower_bound = u64::max(self.lower_bound, rhs.lower_bound);
        if lower_bound == upper_bound {
            return Self {
                lower_bound,
                upper_bound,
                limbs: VecDeque::new(),
            };
        }

        let limbs = ((lower_bound / 32)..=((upper_bound.saturating_sub(1)) / 32))
            .map(|i| {
                let index = i.try_into().expect(
                    "SynchronizationBitMasks cannot handle more limbs than fit in a usize.",
                );
                self.limb(index) | rhs.limb(index)
            })
            .collect::<VecDeque<u32>>();
        Self::Output {
            lower_bound,
            upper_bound,
            limbs,
        }
        .canonize()
    }
}

impl SynchronizationBitMask {
    /// Take a [`SynchronizationBitMask`] not in canonical representation and
    /// put it into canonical representation. Canonical representation means
    /// the `lower_bound` field points to the first zero.
    fn canonize(mut self) -> SynchronizationBitMask {
        // TODO: very slow. improve perf!
        while self.contains(self.lower_bound) {
            self.lower_bound += 1;
            if self.lower_bound.is_multiple_of(32) {
                self.limbs.pop_front();
            }
        }

        if self.lower_bound == self.upper_bound {
            self.limbs = VecDeque::new();
        }

        self
    }

    /// Get the ith limb of the entire bit mask.
    fn limb(&self, index: usize) -> u32 {
        let offset = (self.lower_bound / 32)
            .try_into()
            .expect("SynchronizationBitMasks cannot handle more limbs than fit in a usize.");
        if index < offset {
            return u32::MAX;
        }

        let onset = (self.upper_bound.saturating_sub(1) / 32)
            .try_into()
            .expect("SynchronizationBitMasks cannot handle more limbs than fit in a usize.");
        if index <= onset && !self.limbs.is_empty() {
            return self.limbs[index - offset];
        }

        0
    }

    /// Create a new [`SynchronizationBitMask`] object.
    ///
    /// All bits are initialized to zero. The second argument, `upper_bound` is
    /// exclusive, meaning that the max index is `upper_bound` - 1.
    ///
    /// # Panics
    ///
    ///  - If `upper_bound` <= `lower_bound`.
    ///  - If the would-be number of limbs is greater than usize::MAX.
    pub fn new(lower_bound: u64, upper_bound: u64) -> Self {
        assert!(upper_bound > lower_bound);
        let offset = lower_bound / 32;
        let onset = upper_bound.saturating_sub(1) / 32;
        let num_limbs = if lower_bound == upper_bound {
            0
        } else {
            1_usize + usize::try_from(onset - offset).unwrap()
        };

        let mut limbs = VecDeque::from(vec![0_u32; num_limbs]);

        // set the limb bits below the lower bound
        if let Some(first) = limbs.front_mut() {
            for i in 0..(lower_bound % 32) {
                *first |= 1 << i;
            }
        }

        Self {
            lower_bound,
            upper_bound,
            limbs,
        }
    }

    /// Compute a bitmask whose zeros indicate items that the other does have
    /// and we don't.
    pub fn reconcile(&self, other: &Self) -> Self {
        let offset = self.lower_bound / 32;
        let onset = self.upper_bound.saturating_sub(1) / 32;

        let limbs = (offset..=onset)
            .map(|i| usize::try_from(i).expect("Limb indices fit in usizes."))
            .map(|i| self.limb(i) | !other.limb(i))
            .collect::<VecDeque<u32>>();

        Self {
            lower_bound: self.lower_bound,
            upper_bound: self.upper_bound,
            limbs,
        }
        .canonize()
    }

    /// Increase the upper bound.
    ///
    /// Set all new bits to zero.
    ///
    /// # Panics
    ///
    ///  - If the new upper bound is less than the old.
    pub fn expand(self, new_upper_bound: u64) -> Self {
        assert!(new_upper_bound >= self.upper_bound);

        let offset = self.lower_bound / 32;
        let onset = new_upper_bound.saturating_sub(1) / 32;
        let num_limbs = if self.lower_bound == new_upper_bound {
            0
        } else {
            1_usize + usize::try_from(onset - offset).unwrap()
        };

        let extra_limbs = num_limbs.saturating_sub(self.limbs.len());
        let new_limbs = self
            .limbs
            .into_iter()
            .chain(std::iter::repeat_n(0u32, extra_limbs))
            .collect::<VecDeque<u32>>();
        Self {
            lower_bound: self.lower_bound,
            upper_bound: new_upper_bound,
            limbs: new_limbs,
        }
    }

    /// Determine whether the ith bit is set.
    ///
    /// # Panics
    ///  - If the limb index corresponding to the given bit index is smaller
    ///    than usize::MAX.
    pub fn contains(&self, index: u64) -> bool {
        if index < self.lower_bound {
            return true;
        } else if index >= self.upper_bound {
            return false;
        }

        let limb_index = usize::try_from(index / 32).unwrap();
        let offset = usize::try_from(self.lower_bound / 32).unwrap();

        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        self.limbs[limb_index - offset] & mask != 0
    }

    /// Set the ith bit.
    ///
    /// Ensure it is set to one.
    ///
    /// # Panics
    ///
    ///  - If the given index is greater than or equal to the upper bound.
    pub fn set(&mut self, index: u64) {
        if index < self.lower_bound {
            return;
        }

        assert!(index < self.upper_bound);
        if self.lower_bound == self.upper_bound {
            return;
        }

        let limb_index = usize::try_from(index / 32).unwrap();
        let offset = usize::try_from(self.lower_bound / 32).unwrap();
        if limb_index < offset {
            return;
        }

        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        self.limbs[limb_index - offset] |= mask;

        *self = self.clone().canonize();
    }

    /// Return the vector of indices of unset bits in between lower bound and
    /// upper bound.
    pub fn to_vec_complement(&self) -> Vec<u64> {
        (self.lower_bound..self.upper_bound)
            .filter(|i| !self.contains(*i))
            .collect_vec()
    }

    /// Sample an index between lower and upper bounds whose corresponding bit
    /// is zero.
    ///
    /// # Panics
    ///
    ///  - If lower bound >= upper bound.
    pub fn sample(&self, seed: [u8; 32]) -> u64 {
        let [single_element] = self.sample_many(seed);
        single_element
    }

    /// Sample an index between lower and upper bounds with the given value. Do
    /// this many times.
    ///
    /// The distribution is not uniform but biased towards the lower bound.
    ///
    /// # Panics
    ///
    ///  - If lower bound >= upper bound.
    pub fn sample_many<const N: usize>(&self, seed: [u8; 32]) -> [u64; N] {
        assert_ne!(self.lower_bound, self.upper_bound);
        let mut rng = StdRng::from_seed(seed);
        let mut elements = vec![];
        let mut num_misses = 0;
        while elements.len() != N {
            let index = if rng.random_bool(0.5f64) {
                rng.random_range(
                    self.lower_bound..u64::min(self.upper_bound, self.lower_bound + 10),
                )
            } else {
                rng.random_range(self.lower_bound..self.upper_bound)
            };
            if !self.contains(index) {
                elements.push(index);
            } else {
                num_misses += 1;
                if num_misses > 10 * (1 + elements.len()) {
                    let remainder = self.sample_many_densified(N - elements.len(), rng.random());
                    return [elements, remainder].concat().try_into().unwrap();
                }
            }
        }

        elements.try_into().unwrap()
    }

    fn sample_many_densified(&self, len: usize, seed: [u8; 32]) -> Vec<u64> {
        let mut rng = StdRng::from_seed(seed);
        let list = self.to_vec_complement();
        let mut elements = vec![];
        while elements.len() != len {
            elements.push(list[rng.random_range(0..list.len())]);
        }
        elements
    }

    /// Determine whether all bits up to the upper bound are set.
    pub fn is_complete(&self) -> bool {
        // Canonicity requires that the lower bound be set as high as possible,
        // i.e. it is the index of the first zero. If the bit mask is complete,
        // then the first zero is exactly the point where the infinte string of
        // zeros starts.
        self.lower_bound == self.upper_bound
    }

    /// Count the number of ones between the lower and upper bounds.
    pub fn pop_count(&self) -> u64 {
        let mut pop_count = 0u64;
        for (i, limb) in self.limbs.iter().copied().enumerate() {
            if limb == 0 {
                continue;
            }

            if i == 0 && !self.lower_bound.is_multiple_of(32) {
                let mask = (1 << (self.lower_bound % 32)) - 1;
                pop_count += u64::from((limb & (!mask)).count_ones());
            } else if i == self.limbs.len() - 1 && !self.upper_bound.is_multiple_of(32) {
                let mask = (1 << (self.upper_bound % 32)) - 1;
                pop_count += u64::from((limb & mask).count_ones());
            } else {
                pop_count += u64::from(limb.count_ones());
            }
        }
        pop_count
    }

    /// Set bits min through max (ends inclusive).
    ///
    /// # Panics
    ///
    ///  - If either of the given indices is greater than the upper bound.
    ///  - If max < min.
    pub fn set_range(&mut self, min: u64, max: u64) {
        assert!(max < self.upper_bound);
        assert!(min < self.upper_bound);
        assert!(max >= min);
        let first_full_limb = min.div_ceil(32);
        let first_index_in_full_limb = min.div_ceil(32) * 32;
        let successor_of_last_full_limb = max / 32;
        let first_index_after_last_full_limb = successor_of_last_full_limb * 32;
        let offset = usize::try_from(self.lower_bound / 32).unwrap();

        for limb_i in first_full_limb..successor_of_last_full_limb {
            self.limbs[limb_i as usize - offset] = u32::MAX;
        }
        for index in min..u64::min(max, first_index_in_full_limb) {
            self.set(index);
        }
        for index in u64::max(min, first_index_after_last_full_limb)..=max {
            self.set(index);
        }
    }
}
