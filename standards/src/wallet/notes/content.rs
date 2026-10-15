use std::fmt::Debug;

use nyks_consensus::BFieldElement;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::twenty_first::math::bfield_codec::BFieldCodec;
use nyks_consensus::twenty_first::tip5::Digest;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

/// Errors that can occur when working with [`NoteContent`].
#[derive(Debug, Error)]
pub enum NoteContentError {
    #[error("empty sequence: expected at least a discriminant element")]
    EmptySequence,

    #[error("unknown content discriminant: {0}")]
    UnknownDiscriminant(u64),

    // Boxed because each content type has its own BFieldCodec::Error type.
    // One Decode variant can then handle all of them.
    #[error("failed to decode content: {0}")]
    Decode(Box<dyn std::error::Error + Send + Sync>),
}

/// UTXO notification payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BFieldCodec)]
pub struct UtxoContent {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
}

impl UtxoContent {
    pub const DISCRIMINANT: u64 = 0;

    pub fn new(utxo: Utxo, sender_randomness: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
        }
    }
}

/// Text message payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BFieldCodec)]
pub struct MessageContent {
    pub message: Vec<u8>,
}

impl MessageContent {
    pub const DISCRIMINANT: u64 = 1;

    /// Also adds an 8-byte random suffix, separated from the message by a space.
    pub fn new(message: impl Into<String>) -> Self {
        let mut message = message.into().into_bytes();
        message.push(b' ');
        message.extend_from_slice(&rand::random::<u64>().to_be_bytes());

        Self { message }
    }

    /// Create message content without a random suffix.
    /// Encrypting identical content under the same key reuses its nonce. Use only
    /// for unencrypted content or when nonce uniqueness is handled elsewhere.
    pub fn without_random_suffix(message: impl Into<String>) -> Self {
        Self {
            message: message.into().into_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteContent {
    Utxo(UtxoContent),
    Message(MessageContent),
}

impl NoteContent {
    /// Returns the discriminant of the contained content.
    pub fn discriminant(&self) -> u64 {
        match self {
            Self::Utxo(_) => UtxoContent::DISCRIMINANT,
            Self::Message(_) => MessageContent::DISCRIMINANT,
        }
    }
}

impl From<UtxoContent> for NoteContent {
    fn from(u: UtxoContent) -> Self {
        Self::Utxo(u)
    }
}

impl From<MessageContent> for NoteContent {
    fn from(message: MessageContent) -> Self {
        Self::Message(message)
    }
}

impl BFieldCodec for NoteContent {
    type Error = NoteContentError;

    fn encode(&self) -> Vec<BFieldElement> {
        let (discriminant, mut payload) = match self {
            Self::Utxo(u) => (UtxoContent::DISCRIMINANT, u.encode()),
            Self::Message(message) => (MessageContent::DISCRIMINANT, message.encode()),
        };

        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(BFieldElement::new(discriminant));
        out.append(&mut payload);
        out
    }

    fn decode(sequence: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        let (disc_elem, rest) = sequence
            .split_first()
            .ok_or(NoteContentError::EmptySequence)?;
        let discriminant = disc_elem.value();

        match discriminant {
            d if d == UtxoContent::DISCRIMINANT => {
                let content =
                    UtxoContent::decode(rest).map_err(|e| NoteContentError::Decode(e.into()))?;
                Ok(Box::new(Self::Utxo(*content)))
            }
            d if d == MessageContent::DISCRIMINANT => {
                let message =
                    MessageContent::decode(rest).map_err(|e| NoteContentError::Decode(e.into()))?;
                Ok(Box::new(Self::Message(*message)))
            }
            _ => Err(NoteContentError::UnknownDiscriminant(discriminant)),
        }
    }

    fn static_length() -> Option<usize> {
        // Variable-length: total size depends on which variant is encoded.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_content() -> UtxoContent {
        UtxoContent::new(Utxo::empty_dummy(), Digest::default())
    }

    #[test]
    fn utxo_content_round_trips_through_note_content() {
        let utxo_content = dummy_content();
        let note_content: NoteContent = utxo_content.clone().into();

        // discriminant() + the From<UtxoContent> impl
        assert_eq!(note_content.discriminant(), UtxoContent::DISCRIMINANT);
        assert_eq!(note_content, NoteContent::Utxo(utxo_content));

        // encode(): discriminant is written first
        let encoded = note_content.encode();
        assert_eq!(encoded[0], BFieldElement::new(UtxoContent::DISCRIMINANT));

        // decode(): success path, including the `Self::Utxo` reconstruction
        let decoded = *NoteContent::decode(&encoded).expect("valid encoding must decode");
        assert_eq!(decoded, note_content);
    }

    #[test]
    fn message_content_round_trips_through_note_content() {
        let message = MessageContent::new("Hello, Nyks!");
        let content: NoteContent = message.clone().into();

        assert_eq!(content.discriminant(), MessageContent::DISCRIMINANT);
        assert_eq!(content, NoteContent::Message(message));

        // Encoding prefixes the message payload with the message discriminant.
        let encoded = content.encode();
        assert_eq!(encoded[0], BFieldElement::new(MessageContent::DISCRIMINANT));

        // Decoding the encoded content reconstructs the original value.
        assert_eq!(*NoteContent::decode(&encoded).unwrap(), content);
    }

    #[test]
    fn decode_rejects_invalid_sequences() {
        // Empty sequence: no discriminant element at all.
        let err = NoteContent::decode(&[]).unwrap_err();
        assert!(matches!(err, NoteContentError::EmptySequence));

        // Unknown discriminant: valid element, but not one we recognize.
        let err = NoteContent::decode(&[BFieldElement::new(67)]).unwrap_err();
        assert!(matches!(err, NoteContentError::UnknownDiscriminant(67)));

        // Known discriminant, but the payload behind it is truncated, so the
        // inner UtxoContent::decode fails and gets wrapped as `Decode`.
        let err =
            NoteContent::decode(&[BFieldElement::new(UtxoContent::DISCRIMINANT)]).unwrap_err();
        assert!(matches!(err, NoteContentError::Decode(_)));
    }
}
