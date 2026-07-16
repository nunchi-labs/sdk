//! WebAuthn / passkey types for browser wallets.
//!
//! Encoding follows Commonware Constantinople's secp256r1 assertion layout so SDK
//! chains can verify passkey signatures on-chain when enabled.

/// secp256r1 scheme tag used by Constantinople-style passkey transactions.
pub const SECP256R1_SCHEME: u8 = 1;

/// Maximum authenticator data bytes accepted in a passkey assertion.
pub const WEBAUTHN_AUTHENTICATOR_DATA_BYTES: usize = 256;

/// Maximum client data JSON bytes accepted in a passkey assertion.
pub const WEBAUTHN_CLIENT_DATA_JSON_BYTES: usize = 512;

/// Compressed P-256 public key prefixed with the scheme tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyPublicKey {
    pub scheme: u8,
    pub compressed: [u8; 33],
}

/// Raw passkey assertion material produced by a browser wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyAssertion {
    pub raw_signature: [u8; 64],
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

impl PasskeyAssertion {
    /// Encode the assertion into Nunchi's Constantinople-compatible transaction signature bytes.
    pub fn encode(&self) -> Result<Vec<u8>, PasskeyEncodeError> {
        if self.authenticator_data.len() > WEBAUTHN_AUTHENTICATOR_DATA_BYTES {
            return Err(PasskeyEncodeError::AuthenticatorDataTooLarge);
        }
        if self.client_data_json.len() > WEBAUTHN_CLIENT_DATA_JSON_BYTES {
            return Err(PasskeyEncodeError::ClientDataJsonTooLarge);
        }

        let mut out = Vec::with_capacity(
            1 + 64 + 2 + self.authenticator_data.len() + 2 + self.client_data_json.len(),
        );
        out.push(SECP256R1_SCHEME);
        out.extend_from_slice(&self.raw_signature);
        out.extend_from_slice(&(self.authenticator_data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.authenticator_data);
        out.extend_from_slice(&(self.client_data_json.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.client_data_json);
        Ok(out)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PasskeyEncodeError {
    #[error("authenticator data exceeds {WEBAUTHN_AUTHENTICATOR_DATA_BYTES} bytes")]
    AuthenticatorDataTooLarge,
    #[error("client data JSON exceeds {WEBAUTHN_CLIENT_DATA_JSON_BYTES} bytes")]
    ClientDataJsonTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_constantinople_compatible_assertion() {
        let assertion = PasskeyAssertion {
            raw_signature: [7u8; 64],
            authenticator_data: vec![1, 2, 3],
            client_data_json: br#"{"type":"webauthn.get"}"#.to_vec(),
        };
        let encoded = assertion.encode().expect("encode");
        assert_eq!(encoded[0], SECP256R1_SCHEME);
        assert!(encoded.len() > 70);
    }
}
