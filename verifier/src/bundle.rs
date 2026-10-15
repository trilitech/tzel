use anyhow::{anyhow, Result};
use tzel_core::F as RawF;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofBundle {
    #[serde(with = "tzel_core::hex_bytes")]
    pub proof_bytes: Vec<u8>,
    #[serde(with = "tzel_core::hex_f_vec")]
    pub output_preimage: Vec<RawF>,
}

/// Magic prefix inside the zstd-compressed payload identifying a `leanVM` STARK proof.
pub const LEANVM_PROOF_MAGIC: &[u8; 4] = b"LVM1";

fn leanvm_program() -> &'static leanvm::Program {
    static PROGRAM: std::sync::OnceLock<leanvm::Program> = std::sync::OnceLock::new();
    PROGRAM.get_or_init(|| {
        leanvm::Program::from_elf(tzel_host::ELF).expect("compiled-in tzel.elf must be valid")
    })
}

impl ProofBundle {
    pub fn from_proof_parts(proof_bytes: Vec<u8>, output_preimage: Vec<RawF>) -> Self {
        Self {
            proof_bytes,
            output_preimage,
        }
    }

    /// Encode a raw `leanvm::Proof` (`proof.to_bytes()`) with the `LVM1` magic tag and zstd compression.
    pub fn encode_leanvm_proof_bytes(raw_leanvm_proof: &[u8]) -> Result<Vec<u8>> {
        let mut tagged = Vec::with_capacity(LEANVM_PROOF_MAGIC.len() + raw_leanvm_proof.len());
        tagged.extend_from_slice(LEANVM_PROOF_MAGIC);
        tagged.extend_from_slice(raw_leanvm_proof);
        zstd::encode_all(&tagged[..], 3).map_err(|e| anyhow!("zstd compress leanVM proof: {e}"))
    }

    pub fn proof_bytes(&self) -> Vec<u8> {
        self.proof_bytes.clone()
    }

    fn verify_leanvm(&self, raw_leanvm_proof: &[u8]) -> Result<()> {
        let preimage_felts: Vec<tzel_host::Felt> = self
            .output_preimage
            .iter()
            .map(tzel_host::felt_from_bytes_le)
            .collect();
        let expected_output = tzel_host::validate_and_digest_preimage(&preimage_felts)
            .map_err(|e| anyhow!("circuit verification FAILED: {e}"))?;
        let proof = leanvm::Proof::from_bytes(raw_leanvm_proof)
            .map_err(|e| anyhow!("deserialize leanVM proof: {e}"))?;
        leanvm_program()
            .verify(expected_output.into(), &proof)
            .map_err(|e| anyhow!("circuit verification FAILED: {e}"))?;
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        let compressed = self.proof_bytes();
        let proof_bytes =
            zstd::decode_all(&compressed[..]).map_err(|e| anyhow!("zstd decompress: {e}"))?;
        let raw_leanvm_proof = proof_bytes
            .strip_prefix(LEANVM_PROOF_MAGIC)
            .ok_or_else(|| anyhow!("circuit verification FAILED: missing LVM1 proof header"))?;
        self.verify_leanvm(raw_leanvm_proof)
    }
}
