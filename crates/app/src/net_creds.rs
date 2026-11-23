//! Arke's own credential store for SMB shares, a portable companion to Windows Credential
//! Manager.
//!
//! Windows keeps "remembered" network passwords in the profile, so they don't follow a portable
//! copy. This store keeps them next to the settings instead (`paths::settings_dir`), encrypted
//! with AES-256-CBC and authenticated with HMAC-SHA256 through Windows CNG. The random key lives
//! in a file beside the store, so whoever can read that folder can decrypt the passwords: this
//! keeps them out of the profile and the registry, it is not a defence against a stolen drive.
//!
//! A failed read (missing, corrupt, wrong key) yields an empty store; a failed write is logged
//! and the connection still works, with Windows Credential Manager as the fallback.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paths;

const STORE_FILE: &str = "net_credentials.json";
const KEY_FILE: &str = "net_credentials.key";
/// 32 bytes for AES, 32 for the MAC.
const KEY_LEN: usize = 64;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;
const BLOCK_LEN: usize = 64;

#[derive(Serialize, Deserialize, Default)]
struct Store {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    /// Lower-cased `\\server\share`, without a trailing backslash.
    target: String,
    user: String,
    iv: String,
    mac: String,
    data: String,
}

/// Saved credentials, in memory. The password is held only until the dialog uses it.
pub(crate) struct Credentials {
    dir: PathBuf,
    store: Store,
    key: Vec<u8>,
}

impl Credentials {
    /// Loads the store and its key from `dir` (the settings folder; see `paths`). Missing or
    /// unreadable files mean an empty store and a fresh key.
    pub(crate) fn load(dir: &Path) -> Self {
        let store = std::fs::read(dir.join(STORE_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Store>(&bytes).ok())
            .unwrap_or_default();
        let key = std::fs::read(dir.join(KEY_FILE))
            .ok()
            .filter(|k| k.len() == KEY_LEN)
            .unwrap_or_else(|| {
                let key = random_key();
                if std::fs::create_dir_all(dir).is_ok()
                    && let Err(err) = std::fs::write(dir.join(KEY_FILE), &key)
                {
                    log::warn!("cannot write the credential key: {err}");
                }
                key
            });
        Self {
            dir: dir.to_path_buf(),
            store,
            key,
        }
    }

    /// Saved user name and password for `share`, if any.
    pub(crate) fn get(&self, share: &Path) -> Option<(String, String)> {
        let target = target_key(share);
        let entry = self.store.entries.iter().find(|e| e.target == target)?;
        let iv = from_hex(&entry.iv)?;
        let mac = from_hex(&entry.mac)?;
        let data = from_hex(&entry.data)?;
        let plain = decrypt(&self.key, &iv, &mac, &data)?;
        let password = String::from_utf8(plain).ok()?;
        Some((entry.user.clone(), password))
    }

    /// Remembers (or replaces) the credentials for `share` and writes the store.
    pub(crate) fn put(&mut self, share: &Path, user: &str, password: &str) {
        if user.is_empty() || password.is_empty() {
            return;
        }
        let Some((iv, mac, data)) = encrypt(&self.key, password.as_bytes()) else {
            log::warn!("cannot encrypt the saved network credentials");
            return;
        };
        let target = target_key(share);
        self.store.entries.retain(|e| e.target != target);
        self.store.entries.push(Entry {
            target,
            user: user.to_owned(),
            iv: to_hex(&iv),
            mac: to_hex(&mac),
            data: to_hex(&data),
        });
        self.save();
    }

    fn save(&self) {
        let Ok(json) = serde_json::to_vec_pretty(&self.store) else {
            return;
        };
        let path = self.dir.join(STORE_FILE);
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, &path)).is_err() {
            log::warn!("cannot write {}", path.display());
        }
    }

    /// Forgets the credentials for `share` and writes the store.
    pub(crate) fn remove(&mut self, share: &Path) {
        let target = target_key(share);
        if self.store.entries.iter().any(|e| e.target == target) {
            self.store.entries.retain(|e| e.target != target);
            self.save();
        }
    }
}

/// Credentials for `share` from the settings folder, if the store has them.
pub(crate) fn get(share: &Path) -> Option<(String, String)> {
    let dir = paths::settings_dir()?;
    Credentials::load(&dir).get(share)
}

/// Remembers the credentials for `share` in the settings folder.
pub(crate) fn put(share: &Path, user: &str, password: &str) {
    let Some(dir) = paths::settings_dir() else {
        return;
    };
    let mut credentials = Credentials::load(&dir);
    credentials.put(share, user, password);
}

/// Forgets the credentials for `share` in the settings folder.
pub(crate) fn remove(share: &Path) {
    let Some(dir) = paths::settings_dir() else {
        return;
    };
    let mut credentials = Credentials::load(&dir);
    credentials.remove(share);
}

/// `\\server\share` without a trailing backslash, lower-cased.
fn target_key(share: &Path) -> String {
    share
        .to_string_lossy()
        .trim_end_matches('\\')
        .to_lowercase()
}

fn random_key() -> Vec<u8> {
    use windows::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut key = vec![0u8; KEY_LEN];
    // SAFETY: `key` is a valid writable buffer of the reported length.
    let status = unsafe { BCryptGenRandom(None, &mut key, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if !status.is_ok() {
        // Extremely unlikely (no RNG); a zero key would still be better than nothing but is
        // predictable, so fall back to a hash of the clock and the process id.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let mut digest = Sha256::new();
        digest.update(now.to_le_bytes());
        digest.update(std::process::id().to_le_bytes());
        let fallback = digest.finalize();
        key.iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = fallback[i % fallback.len()]);
    }
    key
}

/// AES-256-CBC with a random IV, then HMAC-SHA256 over the IV and the ciphertext.
fn encrypt(key: &[u8], plain: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let iv = {
        let mut iv = vec![0u8; IV_LEN];
        use windows::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };
        // SAFETY: `iv` is a valid writable buffer of the reported length.
        let status = unsafe { BCryptGenRandom(None, &mut iv, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if !status.is_ok() {
            return None;
        }
        iv
    };
    let data = aes_cbc_encrypt(&key[..32], &iv, plain)?;
    let mac = hmac_sha256(&key[32..], &[&iv, &data]);
    Some((iv, mac.to_vec(), data))
}

/// Verifies the MAC and decrypts; `None` on any mismatch.
fn decrypt(key: &[u8], iv: &[u8], mac: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if mac.len() != MAC_LEN || iv.len() != IV_LEN {
        return None;
    }
    let expected = hmac_sha256(&key[32..], &[iv, data]);
    if !same_bytes(mac, &expected) {
        return None;
    }
    aes_cbc_decrypt(&key[..32], iv, data)
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        BCRYPT_AES_ALGORITHM, BCRYPT_BLOCK_PADDING, BCRYPT_KEY_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCryptCloseAlgorithmProvider, BCryptDestroyKey,
        BCryptEncrypt, BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider,
    };
    // SAFETY: all handles are closed and destroyed on every path; the buffers outlive the calls
    // and are valid for their reported lengths.
    unsafe {
        let mut alg = Default::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_AES_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        if !status.is_ok() {
            return None;
        }
        let mut handle = BCRYPT_KEY_HANDLE::default();
        if !BCryptGenerateSymmetricKey(alg, &mut handle, None, key, 0).is_ok() {
            let _ = BCryptCloseAlgorithmProvider(alg, 0);
            return None;
        }
        let mut len = 0u32;
        let mut iv_copy = iv.to_vec();
        let _ = BCryptEncrypt(
            handle,
            Some(data),
            None,
            Some(&mut iv_copy),
            None,
            &mut len,
            BCRYPT_BLOCK_PADDING,
        );
        let mut out = vec![0u8; len as usize];
        let mut iv_copy = iv.to_vec();
        let ok = BCryptEncrypt(
            handle,
            Some(data),
            None,
            Some(&mut iv_copy),
            Some(&mut out),
            &mut len,
            BCRYPT_BLOCK_PADDING,
        )
        .is_ok();
        let _ = BCryptDestroyKey(handle);
        let _ = BCryptCloseAlgorithmProvider(alg, 0);
        if ok {
            out.truncate(len as usize);
            Some(out)
        } else {
            None
        }
    }
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use windows::Win32::Security::Cryptography::{
        BCRYPT_AES_ALGORITHM, BCRYPT_BLOCK_PADDING, BCRYPT_KEY_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCryptCloseAlgorithmProvider, BCryptDecrypt,
        BCryptDestroyKey, BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider,
    };
    // SAFETY: all handles are closed and destroyed on every path; the buffers outlive the calls
    // and are valid for their reported lengths.
    unsafe {
        let mut alg = Default::default();
        let status = BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_AES_ALGORITHM,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        if !status.is_ok() {
            return None;
        }
        let mut handle = BCRYPT_KEY_HANDLE::default();
        if !BCryptGenerateSymmetricKey(alg, &mut handle, None, key, 0).is_ok() {
            let _ = BCryptCloseAlgorithmProvider(alg, 0);
            return None;
        }
        let mut out = vec![0u8; data.len()];
        let mut len = 0u32;
        let mut iv_copy = iv.to_vec();
        let ok = BCryptDecrypt(
            handle,
            Some(data),
            None,
            Some(&mut iv_copy),
            Some(&mut out),
            &mut len,
            BCRYPT_BLOCK_PADDING,
        )
        .is_ok();
        let _ = BCryptDestroyKey(handle);
        let _ = BCryptCloseAlgorithmProvider(alg, 0);
        if ok {
            out.truncate(len as usize);
            Some(out)
        } else {
            None
        }
    }
}

/// HMAC-SHA256 (RFC 2104) over `parts`, with `key`.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; MAC_LEN] {
    let mut pad = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        pad[..MAC_LEN].copy_from_slice(&Sha256::digest(key));
    } else {
        pad[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_LEN];
    let mut outer_pad = [0x5cu8; BLOCK_LEN];
    for (i, byte) in pad.iter().enumerate() {
        inner_pad[i] ^= byte;
        outer_pad[i] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    for part in parts {
        inner.update(*part);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

/// Constant-time equality, so a wrong MAC doesn't leak how much of it matched.
fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("arke-net-creds-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_password_survives_the_round_trip() {
        let dir = fresh("round");
        let mut store = Credentials::load(&dir);
        let share = Path::new(r"\\NAS\Photos");
        assert!(store.get(share).is_none());
        store.put(share, "sam", "hunter2");
        let (user, password) = store.get(share).expect("the saved credentials");
        assert_eq!((user.as_str(), password.as_str()), ("sam", "hunter2"));
        // A fresh load reads the file, not just the memory.
        let reloaded = Credentials::load(&dir);
        let (user, password) = reloaded.get(share).expect("the stored credentials");
        assert_eq!((user.as_str(), password.as_str()), ("sam", "hunter2"));
        // The file itself holds no plaintext.
        let text = std::fs::read_to_string(dir.join(STORE_FILE)).unwrap();
        assert!(!text.contains("hunter2"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_share_key_ignores_case_and_trailing_slashes() {
        let dir = fresh("case");
        let mut store = Credentials::load(&dir);
        store.put(Path::new(r"\\NAS\Photos"), "sam", "hunter2");
        assert!(store.get(Path::new(r"\\nas\photos\")).is_some());
        assert!(store.get(Path::new(r"\\NAS\Other")).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_tampered_file_or_key_is_dropped() {
        let dir = fresh("tamper");
        let mut store = Credentials::load(&dir);
        store.put(Path::new(r"\\NAS\Photos"), "sam", "hunter2");
        drop(store);
        // Flip a character in the ciphertext.
        let path = dir.join(STORE_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        let flipped = text.replacen('0', "1", 1);
        std::fs::write(&path, flipped).unwrap();
        assert!(Credentials::load(&dir).get(Path::new(r"\\NAS\Photos")).is_none());
        // A different key can't decrypt it either.
        let dir = fresh("key");
        let mut store = Credentials::load(&dir);
        store.put(Path::new(r"\\NAS\Photos"), "sam", "hunter2");
        drop(store);
        std::fs::write(dir.join(KEY_FILE), vec![7u8; KEY_LEN]).unwrap();
        assert!(Credentials::load(&dir).get(Path::new(r"\\NAS\Photos")).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_or_foreign_input_is_ignored() {
        let dir = fresh("empty");
        let mut store = Credentials::load(&dir);
        store.put(Path::new(r"\\NAS\Photos"), "", "hunter2");
        store.put(Path::new(r"\\NAS\Photos"), "sam", "");
        assert!(store.get(Path::new(r"\\NAS\Photos")).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
