//! Identity keys: Ed25519, one per purpose and context, from the phrase the keystore already
//! holds. Pure, like `hd` and `btc`: no I/O and no Logos runtime.
//!
//! **What an identity group keeps** is one SLIP-0010 node, `m/7432'/0'`, the deepest key that
//! still reaches every identity key. The root is never stored, as for every other group. Each
//! identity key sits below the node at eight hardened levels taken from its purpose and context:
//!
//! ```text
//! m / 7432' / 0' / c0' / … / c7'
//!     │       │    └── the first 248 bits of SHA-256(["logos.signer.context.v1",
//!     │       │        {context, purpose}]) in eight 31-bit pieces
//!     │       └─────── 0 = Ed25519
//!     └─────────────── this scheme's purpose level (provisional, unregistered)
//! ```
//!
//! So the same phrase gives the same key for the same purpose and context on every device. Two
//! contexts give two keys nobody can link, and adding one needs the node, never the phrase.
//! SLIP-0010 defines only hardened steps for Ed25519, so the node holds no public half to share:
//! no key below it can be derived without it.
//!
//! Records hashed here are the dCBOR encoding of `[domain, {fields}]`, the same records the
//! callers sign, with keys in bytewise order of their encoding.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::keystore::KeystoreError;

type Result<T> = std::result::Result<T, KeystoreError>;

fn bad(msg: impl Into<String>) -> KeystoreError {
    KeystoreError::InvalidParams(msg.into())
}

/// The family's name, in `groups.json` and in `logos.signer/1`.
pub const FAMILY: &str = "ed25519";

/// The first path level. Provisional: not registered anywhere yet.
pub const PURPOSE: u32 = 7432;

/// The scheme level: Ed25519.
pub const SCHEME_ED25519: u32 = 0;

const HARDENED: u32 = 0x8000_0000;

/// The node's path, as the group record names it.
pub fn node_path() -> String {
    format!("m/{PURPOSE}'/{SCHEME_ED25519}'")
}

// ── records ──────────────────────────────────────────────────────────────────

/// The dCBOR head for a major type and an argument, in its shortest form.
fn head(out: &mut Vec<u8>, major: u8, n: usize) {
    let m = major << 5;
    let n = n as u64;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend([m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(n.to_be_bytes());
    }
}

/// A record field's value: text or bytes, all the records here need.
pub enum Field<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
}

fn item(out: &mut Vec<u8>, f: &Field) {
    match f {
        Field::Text(t) => {
            head(out, 3, t.len());
            out.extend_from_slice(t.as_bytes());
        }
        Field::Bytes(b) => {
            head(out, 2, b.len());
            out.extend_from_slice(b);
        }
    }
}

/// The dCBOR encoding of `[domain, {fields}]`, keys in bytewise order of their encoding.
pub fn record(domain: &str, fields: &[(&str, Field)]) -> Vec<u8> {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = fields
        .iter()
        .map(|(k, v)| {
            let (mut kb, mut vb) = (Vec::new(), Vec::new());
            item(&mut kb, &Field::Text(k));
            item(&mut vb, v);
            (kb, vb)
        })
        .collect();
    pairs.sort();
    let mut out = Vec::new();
    head(&mut out, 4, 2);
    item(&mut out, &Field::Text(domain));
    head(&mut out, 5, pairs.len());
    for (k, v) in pairs {
        out.extend(k);
        out.extend(v);
    }
    out
}

// ── names ────────────────────────────────────────────────────────────────────

/// A purpose is a short lowercase name: `room-identity`, `lez-msig-approval`, …
pub fn check_purpose(s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(bad(format!("purpose must be 1–64 of a–z, 0–9, '-' and '.', got {s:?}")))
    }
}

/// A context is the caller's name for where the key is used: a room, a multisig. Shown, so it
/// must be displayable.
pub fn check_context(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 512 {
        return Err(bad("context must be 1–512 bytes"));
    }
    if s.chars().any(|c| c.is_control() || matches!(c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF)) {
        return Err(bad("context holds a control, bidi or zero-width character"));
    }
    Ok(())
}

/// The eight hardened levels below the node for a purpose and a context.
pub fn context_path(purpose: &str, context: &str) -> Result<[u32; 8]> {
    check_purpose(purpose)?;
    check_context(context)?;
    let h: [u8; 32] = Sha256::digest(record(
        "logos.signer.context.v1",
        &[("purpose", Field::Text(purpose)), ("context", Field::Text(context))],
    ))
    .into();
    let mut out = [0u32; 8];
    let (mut acc, mut bits, mut used) = (0u128, 0u32, 0usize);
    for slot in &mut out {
        while bits < 31 {
            acc = (acc << 8) | h[used] as u128;
            used += 1;
            bits += 8;
        }
        bits -= 31;
        *slot = ((acc >> bits) & 0x7fff_ffff) as u32 | HARDENED;
    }
    Ok(out)
}

// ── SLIP-0010 ────────────────────────────────────────────────────────────────

/// A SLIP-0010 Ed25519 node: its key and its chain code, both wiped on drop.
pub struct Node {
    key: Zeroizing<[u8; 32]>,
    chain: Zeroizing<[u8; 32]>,
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut m = Hmac::<Sha512>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

impl Node {
    fn from_i(i: &[u8; 64]) -> Node {
        let (mut key, mut chain) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        Node { key, chain }
    }

    /// The SLIP-0010 master node of a BIP-39 seed.
    pub fn master(seed: &[u8]) -> Node {
        Node::from_i(&hmac512(b"ed25519 seed", &[seed]))
    }

    /// A hardened child. SLIP-0010 defines no other kind for Ed25519.
    pub fn child(&self, index: u32) -> Node {
        let i = index | HARDENED;
        Node::from_i(&hmac512(&self.chain[..], &[&[0u8], &self.key[..], &i.to_be_bytes()]))
    }

    /// The node an identity group keeps: `m/7432'/0'`.
    pub fn group_node(seed: &[u8]) -> Node {
        Node::master(seed).child(PURPOSE).child(SCHEME_ED25519)
    }

    /// The identity key for a purpose and a context below this node, as its 32-byte Ed25519 seed.
    pub fn identity_key(&self, purpose: &str, context: &str) -> Result<Zeroizing<[u8; 32]>> {
        let path = context_path(purpose, context)?;
        let mut n = self.child(path[0]);
        for &i in &path[1..] {
            n = n.child(i);
        }
        Ok(n.key)
    }

    /// The node's own Ed25519 public key. Public, kept in the group's record, and how a vault is
    /// checked to be this group's before anything is signed with it.
    pub fn public_key(&self) -> [u8; 32] {
        public_key(&self.key)
    }

    /// The vault's text form: key ‖ chain code, hex.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut b = Zeroizing::new([0u8; 64]);
        b[..32].copy_from_slice(&self.key[..]);
        b[32..].copy_from_slice(&self.chain[..]);
        Zeroizing::new(hex::encode(&b[..]))
    }

    pub fn decode(s: &str) -> Result<Node> {
        let b = Zeroizing::new(hex::decode(s.trim()).map_err(|_| KeystoreError::Vault("an identity node is not hex".into()))?);
        let b: &[u8; 64] = b
            .as_slice()
            .try_into()
            .map_err(|_| KeystoreError::Vault("an identity node is 64 bytes".into()))?;
        Ok(Node::from_i(b))
    }
}

/// An Ed25519 seed's public key.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Ed25519 over `message` with the key from `seed`.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer as _;
    ed25519_dalek::SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// An identity account's id in `logos.signer/1`: stable across a restore from the same phrase
/// (the node is the phrase's), and naming no path.
pub fn key_ref(node_public: &[u8; 32], purpose: &str, context: &str) -> String {
    let d = Sha256::digest(record(
        "logos.signer.keyref.v1",
        &[
            ("node", Field::Bytes(node_public)),
            ("scheme", Field::Text(FAMILY)),
            ("purpose", Field::Text(purpose)),
            ("context", Field::Text(context)),
        ],
    ));
    format!("kr_{}", hex::encode(&d[..16]))
}

/// Whether an id names an identity account rather than an address or a group.
pub fn is_key_ref(id: &str) -> bool {
    id.len() == 35 && id.starts_with("kr_") && id[3..].bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED1: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn slip10_ed25519_vector_1() {
        let seed = hex::decode(SEED1).unwrap();
        let m = Node::master(&seed);
        assert_eq!(hex::encode(&m.key[..]), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
        assert_eq!(hex::encode(&m.chain[..]), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb");
        let k = m.child(0);
        assert_eq!(hex::encode(&k.key[..]), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3");
        assert_eq!(hex::encode(k.public_key()), "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c");
        let deep = m.child(0).child(1).child(2).child(2).child(1_000_000_000);
        assert_eq!(hex::encode(&deep.key[..]), "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793");
    }

    #[test]
    fn identity_keys_match_the_proposal_and_the_reference_signer() {
        // The "abandon … about" phrase's BIP-39 seed, empty passphrase.
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let node = Node::group_node(&seed);
        // Held to corpetty/logos-signer-module's derivation of the same path, computed
        // independently there from the root (m/7432'/0'/c0'…c7').
        for (p, c, want) in [
            ("room-identity", "room:a", "c8b57cf9c3cc450e042a6ce6f09b0664859d9a1dd916d75e16d76973b10afbba"),
            ("lez-msig-approval", "ck:0011", "106a7b3a7c8645e8095b2af0c7cbfd9037fb2400e3933708eb7b37fb2dcda935"),
        ] {
            assert_eq!(hex::encode(public_key(&node.identity_key(p, c).unwrap())), want, "{p} {c}");
        }
    }

    #[test]
    fn contexts_purposes_and_phrases_give_unlinkable_keys() {
        let node = Node::group_node(&[1u8; 64]);
        let a = node.identity_key("room-identity", "room:a").unwrap();
        assert_eq!(*a, *node.identity_key("room-identity", "room:a").unwrap(), "deterministic");
        assert_ne!(*a, *node.identity_key("room-identity", "room:b").unwrap());
        assert_ne!(*a, *node.identity_key("lez-member", "room:a").unwrap());
        assert_ne!(*a, *Node::group_node(&[2u8; 64]).identity_key("room-identity", "room:a").unwrap());
    }

    #[test]
    fn the_node_round_trips_and_bad_names_are_refused() {
        let node = Node::group_node(&[3u8; 64]);
        let back = Node::decode(&node.encode()).unwrap();
        assert_eq!(back.public_key(), node.public_key());
        assert!(Node::decode("00").is_err());
        assert!(context_path("Room", "x").is_err());
        assert!(context_path("room-identity", "").is_err());
        assert!(context_path("room-identity", "a\u{202e}b").is_err());
    }

    #[test]
    fn records_encode_as_dcbor_with_bytewise_key_order() {
        // ["d", {"b": "x", "aa": "y"}]: "b" (61 62) sorts before "aa" (62 61 61).
        let r = record("d", &[("aa", Field::Text("y")), ("b", Field::Text("x"))]);
        // 82 | 61 64 | a2 | 61 62, 61 78 | 62 61 61, 61 79
        assert_eq!(hex::encode(r), "826164a2616261786261616179");
    }

    #[test]
    fn key_refs_are_stable_and_recognized() {
        let pk = Node::group_node(&[4u8; 64]).public_key();
        let r = key_ref(&pk, "room-identity", "room:a");
        assert_eq!(r, key_ref(&pk, "room-identity", "room:a"));
        assert_ne!(r, key_ref(&pk, "room-identity", "room:b"));
        assert!(is_key_ref(&r));
        assert!(!is_key_ref("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
        assert!(!is_key_ref("g_0123456789abcdef0123456789abcdef"));
    }
}
