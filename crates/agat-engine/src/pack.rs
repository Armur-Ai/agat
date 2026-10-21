//! Model packs: a trained immune model as a single signed, portable file.
//!
//! A model is the self-model, the negative-selection repertoire, and the
//! clonal memory pool fitted in one agat home. A **pack** bundles the
//! three with a manifest (name, version, families, the antigen metric it
//! was trained in) so the model can be trained once and then deployed to
//! other machines, including air-gapped ones, by copying one file.
//!
//! Integrity and trust:
//!
//! - the payload is stored as exact JSON text alongside its SHA-256, so
//!   any modification is detected;
//! - a pack may carry an **Ed25519 signature** over that digest; import
//!   accepts it only if the signer's public key is explicitly trusted;
//! - unsigned packs are refused unless the operator opts in;
//! - the manifest pins the antigen metric's fingerprint, and import
//!   refuses a pack trained in a different metric space than the running
//!   engine, which would otherwise score every sample against nonsense.
//!
//! A pack contains the training antigens' signature vectors and sample
//! hashes (the self-model's points), never sample bytes.

use agat_antigen::AntigenConfig;
use agat_immune::{MemoryPool, Repertoire, SelfModel};
use agat_store::Store;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{antigen_config, load_memory, load_repertoire, load_self_model, SLOT};

/// Identifier of this pack format; bumped on any incompatible change.
pub const PACK_FORMAT: &str = "agat.pack/v1";

const SIGNING_KEY_HEADER: &str = "agat-signing-key-v1";
const PUBLIC_KEY_HEADER: &str = "agat-public-key-v1";

/// One family the pack can recognize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FamilySummary {
    pub name: String,
    /// Memory cells covering the family.
    pub cells: usize,
    /// Confirmed variants matured into those cells.
    pub variants: u32,
}

/// What the pack is: shown before import and recorded after it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifest {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: String,
    /// agat version that built the pack.
    pub agat_version: String,
    /// The antigen config the model was trained with, and its fingerprint.
    pub antigen: AntigenConfig,
    pub antigen_fingerprint: String,
    pub self_points: usize,
    pub detectors: usize,
    pub families: Vec<FamilySummary>,
}

/// The signed content: manifest plus the three immune structures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackPayload {
    pub manifest: PackManifest,
    pub self_model: SelfModel,
    pub repertoire: Repertoire,
    pub memory: MemoryPool,
}

/// A detached Ed25519 signature over the payload digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackSignature {
    pub algorithm: String,
    pub key_id: String,
    /// Hex Ed25519 public key (32 bytes). Informational: verification
    /// only ever uses keys the operator trusts, never this field.
    pub public_key: String,
    /// Hex Ed25519 signature (64 bytes).
    pub signature: String,
}

/// The on-disk pack file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackFile {
    pub format: String,
    pub payload_sha256: String,
    /// The payload as exact JSON text; the digest and signature cover
    /// these bytes, so no re-serialization can change what was signed.
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PackSignature>,
}

/// Provenance of an installed pack, stored in the agat home and echoed in
/// every scan result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackInfo {
    pub name: String,
    pub version: String,
    pub payload_sha256: String,
    /// Key id of the trusted signer; `None` for an unsigned pack the
    /// operator chose to accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    pub installed_at: String,
}

/// Which packs import accepts.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    pub trusted_keys: Vec<VerifyingKey>,
    pub allow_unsigned: bool,
}

/// A pack that passed every check and is ready to install.
#[derive(Debug, Clone)]
pub struct VerifiedPack {
    pub payload: PackPayload,
    pub payload_sha256: String,
    pub signer: Option<String>,
}

// ---- keys -----------------------------------------------------------

/// A short, stable identifier for a public key: the first 16 hex chars
/// of its SHA-256.
pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))[..16].to_string()
}

/// A fresh signing key from the OS CSPRNG.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Serialize a signing key (secret) in agat's text key format.
pub fn signing_key_to_text(key: &SigningKey) -> String {
    format!("{SIGNING_KEY_HEADER}\n{}\n", hex::encode(key.to_bytes()))
}

/// Serialize a public key in agat's text key format. The optional comment
/// (e.g. "acme-secops 2026") is informational.
pub fn public_key_to_text(key: &VerifyingKey, comment: Option<&str>) -> String {
    let mut line = format!(
        "{PUBLIC_KEY_HEADER} {} {}",
        hex::encode(key.as_bytes()),
        key_id(key)
    );
    if let Some(c) = comment {
        line.push(' ');
        line.push_str(c);
    }
    line.push('\n');
    line
}

/// Parse a signing key written by [`signing_key_to_text`].
pub fn signing_key_from_text(text: &str) -> Result<SigningKey> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    if lines.next() != Some(SIGNING_KEY_HEADER) {
        bail!("not an agat signing key (expected a '{SIGNING_KEY_HEADER}' header)");
    }
    let bytes = hex::decode(lines.next().context("signing key is empty")?)
        .context("signing key is not valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Parse a public key written by [`public_key_to_text`].
pub fn public_key_from_text(text: &str) -> Result<VerifyingKey> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .context("public key file is empty")?;
    let mut parts = line.split_whitespace();
    if parts.next() != Some(PUBLIC_KEY_HEADER) {
        bail!("not an agat public key (expected a '{PUBLIC_KEY_HEADER}' line)");
    }
    let bytes = hex::decode(parts.next().context("public key is missing")?)
        .context("public key is not valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")?;
    if let Some(claimed) = parts.next() {
        if claimed != key_id(&key) {
            bail!("public key file's key id {claimed} does not match the key");
        }
    }
    Ok(key)
}

// ---- export ---------------------------------------------------------

/// Assemble a payload from the model in `store`'s active slot.
pub fn build_payload(
    store: &Store,
    name: &str,
    version: &str,
    description: Option<String>,
) -> Result<PackPayload> {
    let self_model =
        load_self_model(store)?.context("no self-model to export — run `agat self build` first")?;
    let repertoire = load_repertoire(store)?
        .context("no repertoire to export — run `agat repertoire generate` first")?;
    let memory = load_memory(store)?;
    let antigen = antigen_config();

    let mut families: Vec<FamilySummary> = memory
        .families()
        .into_iter()
        .map(|f| {
            let cells: Vec<_> = memory.cells.iter().filter(|c| c.family == f).collect();
            FamilySummary {
                name: f.to_string(),
                cells: cells.len(),
                variants: cells.iter().map(|c| c.variants).sum(),
            }
        })
        .collect();
    families.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(PackPayload {
        manifest: PackManifest {
            name: name.to_string(),
            version: version.to_string(),
            description,
            created_at: chrono::Utc::now().to_rfc3339(),
            agat_version: env!("CARGO_PKG_VERSION").to_string(),
            antigen_fingerprint: antigen.fingerprint(),
            antigen,
            self_points: self_model.points.len(),
            detectors: repertoire.len(),
            families,
        },
        self_model,
        repertoire,
        memory,
    })
}

/// The exact bytes a pack signature covers: the format tag and the
/// payload digest (domain-separated so a pack signature can never be
/// replayed as a signature over anything else).
fn signed_message(payload_sha256: &str) -> Vec<u8> {
    format!("{PACK_FORMAT}:{payload_sha256}").into_bytes()
}

/// Seal a payload into a pack file, signing it if a key is given.
pub fn seal(payload: &PackPayload, key: Option<&SigningKey>) -> Result<PackFile> {
    let text = serde_json::to_string(payload)?;
    let digest = hex::encode(Sha256::digest(text.as_bytes()));
    let signature = key.map(|k| {
        let sig = k.sign(&signed_message(&digest));
        let public = k.verifying_key();
        PackSignature {
            algorithm: "ed25519".to_string(),
            key_id: key_id(&public),
            public_key: hex::encode(public.as_bytes()),
            signature: hex::encode(sig.to_bytes()),
        }
    });
    Ok(PackFile {
        format: PACK_FORMAT.to_string(),
        payload_sha256: digest,
        payload: text,
        signature,
    })
}

// ---- import ---------------------------------------------------------

/// Check a pack's format, integrity, signature, trust, and metric-space
/// compatibility. Nothing is installed; see [`install`].
pub fn verify(pack: &PackFile, policy: &TrustPolicy) -> Result<VerifiedPack> {
    if pack.format != PACK_FORMAT {
        bail!(
            "unsupported pack format '{}' (this agat reads {PACK_FORMAT})",
            pack.format
        );
    }
    let digest = hex::encode(Sha256::digest(pack.payload.as_bytes()));
    if digest != pack.payload_sha256 {
        bail!("pack integrity check failed: payload does not match its SHA-256 (corrupted or tampered)");
    }

    let signer = match &pack.signature {
        None => {
            if !policy.allow_unsigned {
                bail!("pack is unsigned; refusing it (pass --allow-unsigned to accept an unsigned pack)");
            }
            None
        }
        Some(sig) => {
            if sig.algorithm != "ed25519" {
                bail!("unsupported signature algorithm '{}'", sig.algorithm);
            }
            let sig_bytes: [u8; 64] = hex::decode(&sig.signature)
                .context("signature is not valid hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
            let signature = Signature::from_bytes(&sig_bytes);
            let message = signed_message(&digest);
            let trusted = policy
                .trusted_keys
                .iter()
                .find(|k| k.verify(&message, &signature).is_ok());
            match trusted {
                Some(k) => Some(key_id(k)),
                None if policy.trusted_keys.iter().any(|k| key_id(k) == sig.key_id) => {
                    bail!("pack signature is INVALID for trusted key {}: the pack was modified after signing", sig.key_id)
                }
                None => bail!(
                    "pack is signed by key {} which is not trusted (add its public key with --trust)",
                    sig.key_id
                ),
            }
        }
    };

    let payload: PackPayload =
        serde_json::from_str(&pack.payload).context("decoding pack payload")?;
    let expected = antigen_config().fingerprint();
    if payload.manifest.antigen_fingerprint != expected
        || payload.manifest.antigen.fingerprint() != expected
    {
        bail!(
            "pack '{}' was trained in a different antigen metric space ({}…) than this agat ({}…); \
             it would mis-score every sample. Retrain it with this agat version.",
            payload.manifest.name,
            &payload.manifest.antigen_fingerprint[..12.min(payload.manifest.antigen_fingerprint.len())],
            &expected[..12]
        );
    }
    if payload.repertoire.dim != payload.self_model.dim {
        bail!("pack is internally inconsistent: repertoire and self-model dimensions differ");
    }

    Ok(VerifiedPack {
        payload,
        payload_sha256: digest,
        signer,
    })
}

/// Install a verified pack as `store`'s active model, replacing the
/// current self-model, repertoire, and memory, and record its provenance.
pub fn install(store: &Store, pack: &VerifiedPack) -> Result<PackInfo> {
    let p = &pack.payload;
    store.put_self_model(SLOT, &serde_json::to_string(&p.self_model)?)?;
    store.put_repertoire(SLOT, &serde_json::to_string(&p.repertoire)?)?;
    store.put_memory(SLOT, &serde_json::to_string(&p.memory)?)?;
    let info = PackInfo {
        name: p.manifest.name.clone(),
        version: p.manifest.version.clone(),
        payload_sha256: pack.payload_sha256.clone(),
        signer: pack.signer.clone(),
        installed_at: chrono::Utc::now().to_rfc3339(),
    };
    store.put_pack_info(SLOT, &serde_json::to_string(&info)?)?;
    Ok(info)
}

/// Provenance of the pack installed in the active slot, if any.
pub fn installed(store: &Store) -> Result<Option<PackInfo>> {
    match store.get_pack_info(SLOT)? {
        Some(j) => Ok(Some(
            serde_json::from_str(&j).context("decoding pack info")?,
        )),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_antigen::Antigen;
    use agat_immune::{generate_repertoire, mature, ClonalConfig, NsaConfig};
    use std::collections::BTreeSet;

    fn antigen(sig: Vec<f64>) -> Antigen {
        Antigen {
            signature: sig,
            block_tokens: BTreeSet::new(),
            cfg_fingerprint: None,
            plaintext_fingerprint: None,
        }
    }

    /// A store holding a small trained model in the default antigen dim.
    fn trained_store() -> Store {
        let dim = agat_antigen::signature_labels(&antigen_config()).len();
        let point = |v: f64| {
            let mut s = vec![0.1; dim];
            s[0] = v;
            antigen(s)
        };
        let benign: Vec<(String, Antigen)> = (0..4)
            .map(|i| (format!("b{i}"), point(0.1 + i as f64 * 0.01)))
            .collect();
        let labelled: Vec<(&str, &Antigen)> = benign.iter().map(|(n, a)| (n.as_str(), a)).collect();
        let self_model = SelfModel::build(&labelled, 2);
        let repertoire = generate_repertoire(
            &self_model,
            dim,
            &NsaConfig {
                seed: 1,
                ..NsaConfig::default()
            },
        );
        let mut memory = MemoryPool::new(dim);
        for v in [0.9, 0.92, 0.94] {
            mature(
                &point(v),
                "fam",
                &mut memory,
                Some(&repertoire),
                &ClonalConfig::default(),
            );
        }
        let store = Store::open_in_memory().unwrap();
        store
            .put_self_model(SLOT, &serde_json::to_string(&self_model).unwrap())
            .unwrap();
        store
            .put_repertoire(SLOT, &serde_json::to_string(&repertoire).unwrap())
            .unwrap();
        store
            .put_memory(SLOT, &serde_json::to_string(&memory).unwrap())
            .unwrap();
        store
    }

    fn trusting(key: &SigningKey) -> TrustPolicy {
        TrustPolicy {
            trusted_keys: vec![key.verifying_key()],
            allow_unsigned: false,
        }
    }

    #[test]
    fn signed_pack_round_trips_into_a_fresh_store() {
        let src = trained_store();
        let key = generate_signing_key();
        let payload = build_payload(&src, "acme", "1.0", Some("test".into())).unwrap();
        assert_eq!(payload.manifest.families.len(), 1);
        assert_eq!(payload.manifest.families[0].name, "fam");
        assert_eq!(payload.manifest.families[0].variants, 3);

        let file = seal(&payload, Some(&key)).unwrap();
        let text = serde_json::to_string(&file).unwrap();
        let back: PackFile = serde_json::from_str(&text).unwrap();
        let verified = verify(&back, &trusting(&key)).unwrap();
        assert_eq!(
            verified.signer.as_deref(),
            Some(key_id(&key.verifying_key()).as_str())
        );

        let dst = Store::open_in_memory().unwrap();
        let info = install(&dst, &verified).unwrap();
        assert_eq!(info.name, "acme");
        assert_eq!(installed(&dst).unwrap(), Some(info.clone()));
        assert_eq!(
            dst.get_repertoire(SLOT).unwrap(),
            src.get_repertoire(SLOT).unwrap(),
            "repertoire must arrive byte-identical"
        );
        // The installed model is usable by the engine and reports its pack.
        let model = crate::ImmuneModel::load(&dst).unwrap();
        let r = model.model_ref();
        assert_eq!(r.source, "pack");
        assert_eq!(r.name.as_deref(), Some("acme"));
        assert_eq!(r.sha256.as_deref(), Some(info.payload_sha256.as_str()));
        assert_eq!(r.signer, info.signer);
        // A locally trained model says so.
        assert_eq!(
            crate::ImmuneModel::load(&src).unwrap().model_ref().source,
            "local"
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = generate_signing_key();
        let mut file = seal(
            &build_payload(&trained_store(), "a", "1", None).unwrap(),
            Some(&key),
        )
        .unwrap();
        file.payload = file.payload.replacen("\"fam\"", "\"evil\"", 1);
        let err = verify(&file, &trusting(&key)).unwrap_err().to_string();
        assert!(err.contains("integrity"), "{err}");

        // Recomputing the digest doesn't help: the signature no longer matches.
        file.payload_sha256 = hex::encode(Sha256::digest(file.payload.as_bytes()));
        let err = verify(&file, &trusting(&key)).unwrap_err().to_string();
        assert!(err.contains("INVALID"), "{err}");
    }

    #[test]
    fn untrusted_signer_and_unsigned_packs_are_refused_by_default() {
        let payload = build_payload(&trained_store(), "a", "1", None).unwrap();
        let mallory = generate_signing_key();
        let alice = generate_signing_key();

        let signed = seal(&payload, Some(&mallory)).unwrap();
        let err = verify(&signed, &trusting(&alice)).unwrap_err().to_string();
        assert!(err.contains("not trusted"), "{err}");

        let unsigned = seal(&payload, None).unwrap();
        let err = verify(&unsigned, &TrustPolicy::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsigned"), "{err}");
        let ok = verify(
            &unsigned,
            &TrustPolicy {
                allow_unsigned: true,
                ..TrustPolicy::default()
            },
        )
        .unwrap();
        assert!(ok.signer.is_none());
    }

    #[test]
    fn different_metric_space_is_refused() {
        let key = generate_signing_key();
        let mut payload = build_payload(&trained_store(), "a", "1", None).unwrap();
        payload.manifest.antigen.w_entropy = 3.0;
        payload.manifest.antigen_fingerprint = payload.manifest.antigen.fingerprint();
        let file = seal(&payload, Some(&key)).unwrap();
        let err = verify(&file, &trusting(&key)).unwrap_err().to_string();
        assert!(err.contains("antigen metric space"), "{err}");
    }

    #[test]
    fn key_text_formats_round_trip_and_reject_garbage() {
        let key = generate_signing_key();
        let back = signing_key_from_text(&signing_key_to_text(&key)).unwrap();
        assert_eq!(back.to_bytes(), key.to_bytes());
        let public =
            public_key_from_text(&public_key_to_text(&key.verifying_key(), Some("ops team")))
                .unwrap();
        assert_eq!(public, key.verifying_key());

        assert!(signing_key_from_text("hello").is_err());
        assert!(public_key_from_text("agat-public-key-v1 zz").is_err());
        // A key id that doesn't match the key is rejected.
        let mut text = public_key_to_text(&key.verifying_key(), None);
        text = text.replace(&key_id(&key.verifying_key()), "0000000000000000");
        assert!(public_key_from_text(&text).is_err());
    }
}
