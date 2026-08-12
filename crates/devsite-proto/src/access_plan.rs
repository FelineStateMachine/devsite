//! Server-signed approval tokens for endpoint-bound service grants.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGrantPlanClaims {
    pub schema_version: u32,
    pub issuer_credential_id: String,
    pub request_id: String,
    pub service: String,
    pub resource_id: String,
    pub requester_endpoint_id: String,
    pub request_expires_at: u64,
    pub grant_expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedServiceGrantPlan {
    claims: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ServiceGrantPlanError {
    #[error("service grant plan signature does not verify")]
    BadSignature,
    #[error("service grant plan is malformed")]
    Malformed,
}

impl SignedServiceGrantPlan {
    pub fn sign(
        claims: &ServiceGrantPlanClaims,
        key: &SigningKey,
    ) -> Result<Self, ServiceGrantPlanError> {
        let mut bytes = b"dev.site approved service grant plan v1\0".to_vec();
        bytes.extend(postcard::to_allocvec(claims).map_err(|_| ServiceGrantPlanError::Malformed)?);
        Ok(Self {
            signature: key.sign(&bytes).to_bytes().to_vec(),
            claims: bytes,
        })
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
    ) -> Result<ServiceGrantPlanClaims, ServiceGrantPlanError> {
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ServiceGrantPlanError::Malformed)?;
        key.verify(&self.claims, &Signature::from_bytes(&signature))
            .map_err(|_| ServiceGrantPlanError::BadSignature)?;
        let payload = self
            .claims
            .strip_prefix(b"dev.site approved service grant plan v1\0")
            .ok_or(ServiceGrantPlanError::Malformed)?;
        postcard::from_bytes(payload).map_err(|_| ServiceGrantPlanError::Malformed)
    }

    pub fn to_token(&self) -> String {
        let bytes = postcard::to_allocvec(self).expect("a signed service grant plan serializes");
        format!("dsp_{}", data_encoding::BASE64URL_NOPAD.encode(&bytes))
    }

    pub fn from_token(token: &str) -> Result<Self, ServiceGrantPlanError> {
        let encoded = token
            .strip_prefix("dsp_")
            .ok_or(ServiceGrantPlanError::Malformed)?;
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| ServiceGrantPlanError::Malformed)?;
        postcard::from_bytes(&bytes).map_err(|_| ServiceGrantPlanError::Malformed)
    }

    /// Decode untrusted claims for clients that need to reconstruct the exact
    /// request. The server must still verify the signature before authorizing it.
    pub fn unverified_claims(&self) -> Result<ServiceGrantPlanClaims, ServiceGrantPlanError> {
        let payload = self
            .claims
            .strip_prefix(b"dev.site approved service grant plan v1\0")
            .ok_or(ServiceGrantPlanError::Malformed)?;
        postcard::from_bytes(payload).map_err(|_| ServiceGrantPlanError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> ServiceGrantPlanClaims {
        ServiceGrantPlanClaims {
            schema_version: 1,
            issuer_credential_id: "machine_one".into(),
            request_id: "agr_one".into(),
            service: "postgres".into(),
            resource_id: "res_one".into(),
            requester_endpoint_id: "endpoint".into(),
            request_expires_at: 200,
            grant_expires_at: 300,
        }
    }

    #[test]
    fn signed_plan_token_round_trips_and_rejects_another_issuer() {
        let issuer = SigningKey::from_bytes(&[1; 32]);
        let other = SigningKey::from_bytes(&[2; 32]);
        let token = SignedServiceGrantPlan::sign(&claims(), &issuer)
            .unwrap()
            .to_token();
        let restored = SignedServiceGrantPlan::from_token(&token).unwrap();
        assert_eq!(restored.verify(&issuer.verifying_key()).unwrap(), claims());
        assert_eq!(
            restored.verify(&other.verifying_key()),
            Err(ServiceGrantPlanError::BadSignature)
        );
    }
}
