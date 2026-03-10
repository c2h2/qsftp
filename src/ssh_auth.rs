//! SSH public key authentication using challenge-response.
//!
//! Flow:
//! 1. Client sends AuthPubKey { username, pub_key (OpenSSH format string) }
//! 2. Server checks pub_key is in ~/.ssh/authorized_keys
//! 3. If found, server sends AuthChallenge { 32 random bytes }
//! 4. Client signs the challenge with private key, sends AuthPubKeySign { signature }
//! 5. Server verifies signature with the public key

use anyhow::{Context, Result};
use ssh_key::{PrivateKey, PublicKey};
use std::path::{Path, PathBuf};

/// Load the best available private key from ~/.ssh/ or a specified path.
pub fn find_private_key(identity_file: Option<&Path>) -> Result<PrivateKey> {
    if let Some(path) = identity_file {
        return load_private_key(path, true);
    }

    let ssh_dir = dirs_ssh();
    let candidates = ["id_ed25519", "id_ecdsa", "id_rsa"];

    for name in &candidates {
        let path = ssh_dir.join(name);
        if path.exists() {
            match load_private_key(&path, false) {
                Ok(key) => {
                    tracing::info!("Using SSH key: {}", path.display());
                    return Ok(key);
                }
                Err(e) => {
                    tracing::debug!("Skipping {}: {}", path.display(), e);
                }
            }
        }
    }

    anyhow::bail!(
        "No SSH private key found in {}",
        ssh_dir.display()
    )
}

fn load_private_key(path: &Path, prompt_passphrase: bool) -> Result<PrivateKey> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    // Try without passphrase
    match PrivateKey::from_openssh(&data) {
        Ok(key) => return Ok(key),
        Err(e) => {
            if !prompt_passphrase {
                // For auto-discovery, skip encrypted keys silently
                return Err(anyhow::anyhow!("key load failed: {}", e));
            }
            tracing::debug!("Key may be encrypted: {}", e);
        }
    }

    // Try with passphrase
    let passphrase = rpassword::read_password_from_tty(Some(&format!(
        "Enter passphrase for {}: ",
        path.display()
    )))
    .unwrap_or_default();

    if passphrase.is_empty() {
        anyhow::bail!("passphrase required for encrypted key {}", path.display());
    }

    PrivateKey::from_openssh(data.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to load key {}: {}", path.display(), e))
}

/// Get public key in OpenSSH one-line format from a private key
pub fn public_key_openssh(private_key: &PrivateKey) -> String {
    private_key.public_key().to_openssh()
        .unwrap_or_default()
}

/// Sign a challenge with the private key.
/// Returns the raw signature bytes.
pub fn sign_challenge(private_key: &PrivateKey, challenge: &[u8]) -> Result<Vec<u8>> {
    use ssh_key::private::KeypairData;

    match private_key.key_data() {
        KeypairData::Ed25519(kp) => {
            use ed25519_dalek::{Signer, SigningKey};
            let signing_key = SigningKey::from_bytes(&kp.private.to_bytes());
            let sig = signing_key.sign(challenge);
            Ok(sig.to_bytes().to_vec())
        }
        KeypairData::Rsa(kp) => {
            use rsa::pkcs1v15::SigningKey as RsaSigningKey;
            use rsa::signature::Signer as RsaSigner;
            use rsa::signature::SignatureEncoding;
            use sha2::Sha256;

            let private_key_rsa = rsa::RsaPrivateKey::try_from(kp)
                .map_err(|e| anyhow::anyhow!("RSA key conversion: {}", e))?;
            let signing_key = RsaSigningKey::<Sha256>::new(private_key_rsa);
            let sig = signing_key.sign(challenge);
            Ok(sig.to_vec())
        }
        _ => {
            anyhow::bail!("Unsupported key type for signing. Use ed25519 or RSA.");
        }
    }
}

/// Verify a challenge signature against a public key.
pub fn verify_challenge(
    pub_key_openssh: &str,
    challenge: &[u8],
    signature_bytes: &[u8],
) -> Result<bool> {
    let pub_key = PublicKey::from_openssh(pub_key_openssh)
        .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;

    match pub_key.key_data() {
        ssh_key::public::KeyData::Ed25519(ed_pub) => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let vk = VerifyingKey::from_bytes(&ed_pub.0)
                .map_err(|e| anyhow::anyhow!("invalid ed25519 key: {}", e))?;
            if signature_bytes.len() != 64 {
                return Ok(false);
            }
            let sig = Signature::from_bytes(signature_bytes.try_into().unwrap());
            Ok(vk.verify(challenge, &sig).is_ok())
        }
        ssh_key::public::KeyData::Rsa(rsa_pub) => {
            use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
            use rsa::signature::Verifier as RsaVerifier;
            use sha2::Sha256;

            let public_key_rsa = rsa::RsaPublicKey::try_from(rsa_pub)
                .map_err(|e| anyhow::anyhow!("RSA key conversion: {}", e))?;
            let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key_rsa);
            let sig = rsa::pkcs1v15::Signature::try_from(signature_bytes)
                .map_err(|e| anyhow::anyhow!("invalid RSA signature: {}", e))?;
            Ok(verifying_key.verify(challenge, &sig).is_ok())
        }
        _ => {
            tracing::warn!("Unsupported key type for verification");
            Ok(false)
        }
    }
}

/// Check if a public key exists in the user's authorized_keys file.
pub fn check_authorized_keys(username: &str, offered_key_openssh: &str) -> Result<bool> {
    let ak_path = get_authorized_keys_path(username)?;

    if !ak_path.exists() {
        tracing::debug!("No authorized_keys at {}", ak_path.display());
        return Ok(false);
    }

    let contents = std::fs::read_to_string(&ak_path)
        .with_context(|| format!("reading {}", ak_path.display()))?;

    let offered = PublicKey::from_openssh(offered_key_openssh)
        .map_err(|e| anyhow::anyhow!("invalid offered key: {}", e))?;

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(authorized) = PublicKey::from_openssh(line) {
            if authorized.key_data() == offered.key_data() {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Generate 32 random bytes as a challenge
pub fn generate_challenge() -> Vec<u8> {
    use rand::RngCore;
    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge
}

fn get_authorized_keys_path(username: &str) -> Result<PathBuf> {
    let output = std::process::Command::new("getent")
        .args(["passwd", username])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("user '{}' not found", username);
    }
    let line = String::from_utf8(output.stdout)?;
    let home = line.trim().split(':').nth(5).unwrap_or("/tmp");
    Ok(PathBuf::from(home).join(".ssh").join("authorized_keys"))
}

fn dirs_ssh() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".ssh"))
        .unwrap_or_else(|_| PathBuf::from("/root/.ssh"))
}
