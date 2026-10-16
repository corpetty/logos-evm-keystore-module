//! Bitcoin accounts: the BIP84 and BIP86 paths, account keys and descriptors.
//! Pure, like `hd`: no I/O and no Logos runtime.

use std::fmt;
use std::str::FromStr;

use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::key::{CompressedPublicKey, UntweakedPublicKey};
use bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use bitcoin::{Network, NetworkKind, ScriptBuf};

use crate::keystore::KeystoreError;

type Result<T> = std::result::Result<T, KeystoreError>;

fn bad(msg: impl Into<String>) -> KeystoreError {
    KeystoreError::InvalidParams(msg.into())
}

/// The two Bitcoin families a group can be. Each has one fixed purpose level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// Native segwit, P2WPKH, BIP84.
    Segwit,
    /// Taproot key path, P2TR, BIP86.
    Taproot,
}

impl Family {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "bitcoin" => Ok(Self::Segwit),
            "bitcoin_taproot" => Ok(Self::Taproot),
            other => Err(bad(format!("family must be \"bitcoin\" or \"bitcoin_taproot\", got {other:?}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Segwit => "bitcoin",
            Self::Taproot => "bitcoin_taproot",
        }
    }

    pub fn purpose(self) -> u32 {
        match self {
            Self::Segwit => 84,
            Self::Taproot => 86,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Segwit => "native segwit",
            Self::Taproot => "taproot",
        }
    }
}

/// Mainnet, or the test networks, which BIP44 gives coin type 1 together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Main,
    Test,
}

impl Chain {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "main" => Ok(Self::Main),
            "test" => Ok(Self::Test),
            other => Err(bad(format!("network must be \"main\" or \"test\", got {other:?}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Test => "test",
        }
    }

    pub fn coin_type(self) -> u32 {
        match self {
            Self::Main => 0,
            Self::Test => 1,
        }
    }

    pub fn kind(self) -> NetworkKind {
        match self {
            Self::Main => NetworkKind::Main,
            Self::Test => NetworkKind::Test,
        }
    }

    /// A network a request names. It has to belong to this chain: a test wallet never signs for mainnet.
    pub fn network(self, name: &str) -> Result<Network> {
        let net = match name.trim() {
            "bitcoin" | "main" | "mainnet" => Network::Bitcoin,
            "testnet" | "testnet3" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            other => return Err(bad(format!("unknown Bitcoin network {other:?}"))),
        };
        if NetworkKind::from(net) != self.kind() {
            return Err(bad(format!("this wallet is on the {} chain and can't sign for {net}", self.as_str())));
        }
        Ok(net)
    }
}

/// How the signer names a network.
pub fn network_name(net: Network) -> &'static str {
    match net {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

const HARDENED: u32 = 0x8000_0000;

/// `m/<purpose>'/<coin>'/<account>'`, the deepest key a Bitcoin group keeps.
pub fn account_path(family: Family, chain: Chain, account: u32) -> Result<DerivationPath> {
    if account >= HARDENED {
        return Err(bad(format!("account must be below 2^31, got {account}")));
    }
    let level = |i: u32| ChildNumber::from_hardened_idx(i).map_err(|e| bad(e.to_string()));
    Ok(DerivationPath::from(vec![level(family.purpose())?, level(chain.coin_type())?, level(account)?]))
}

/// Parse a stored account path and return its account. Anything but this family's and chain's prefix is refused.
pub fn parse_account_path(s: &str, family: Family, chain: Chain) -> Result<u32> {
    if !s.starts_with("m/") {
        return Err(bad(format!("path {s:?} must start with \"m/\"")));
    }
    let path = DerivationPath::from_str(s).map_err(|e| bad(format!("path {s:?}: {e}")))?;
    let levels: Vec<ChildNumber> = path.into_iter().copied().collect();
    let [p, c, ChildNumber::Hardened { index: a }] = levels.as_slice() else {
        return Err(bad(format!("path {s:?} is not m/{}'/{}'/<account>'", family.purpose(), chain.coin_type())));
    };
    if *p != (ChildNumber::Hardened { index: family.purpose() }) || *c != (ChildNumber::Hardened { index: chain.coin_type() }) {
        return Err(bad(format!("path {s:?} is not m/{}'/{}'/<account>'", family.purpose(), chain.coin_type())));
    }
    Ok(*a)
}

/// A Bitcoin account key, live only for the caller's scope.
///
/// rust-bitcoin's `Xpriv` is `Copy` and can't be zeroized, so this wipes its own copy on drop and no more.
pub struct AccountSecret {
    xprv: Xpriv,
}

impl Drop for AccountSecret {
    fn drop(&mut self) {
        self.xprv.private_key.non_secure_erase();
        self.xprv.chain_code = ChainCode::from([0u8; 32]);
    }
}

impl fmt::Debug for AccountSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountSecret(<redacted>)")
    }
}

/// A BIP39 seed's master fingerprint: which wallet it is, the same on every network and for every
/// family, so an EVM account names the wallet it comes from as a Bitcoin one does.
pub fn master_fingerprint(seed: &[u8]) -> Result<Fingerprint> {
    let secp = Secp256k1::signing_only();
    let mut master = Xpriv::new_master(NetworkKind::Main, seed).map_err(|e| bad(format!("bip32: {e}")))?;
    let fingerprint = master.fingerprint(&secp);
    master.private_key.non_secure_erase();
    master.chain_code = ChainCode::from([0u8; 32]);
    Ok(fingerprint)
}

impl AccountSecret {
    /// The account key and the master fingerprint, from a BIP39 seed.
    pub fn from_seed<C: Signing>(
        secp: &Secp256k1<C>,
        seed: &[u8],
        family: Family,
        chain: Chain,
        account: u32,
    ) -> Result<(Self, Fingerprint)> {
        let mut master = Xpriv::new_master(chain.kind(), seed).map_err(|e| bad(format!("bip32: {e}")))?;
        let fingerprint = master.fingerprint(secp);
        let derived = master.derive_priv(secp, &account_path(family, chain, account)?);
        master.private_key.non_secure_erase();
        master.chain_code = ChainCode::from([0u8; 32]);
        let xprv = derived.map_err(|e| bad(format!("bip32: {e}")))?;
        Ok((Self { xprv }, fingerprint))
    }

    /// Read a stored account key back, refusing anything but an account-level key of this chain.
    pub fn decode(s: &str, chain: Chain) -> Result<Self> {
        let xprv = Xpriv::from_str(s.trim()).map_err(|e| KeystoreError::Vault(format!("account key: {e}")))?;
        let key = Self { xprv };
        if key.xprv.depth != 3 || key.xprv.network != chain.kind() {
            return Err(KeystoreError::Vault("the stored key is not this wallet's account key".into()));
        }
        Ok(key)
    }

    pub fn encode(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(self.xprv.to_string())
    }

    pub fn xpub<C: Signing>(&self, secp: &Secp256k1<C>) -> Xpub {
        Xpub::from_priv(secp, &self.xprv)
    }

    pub(crate) fn xprv(&self) -> &Xpriv {
        &self.xprv
    }
}

/// What a Bitcoin group shows the world: no secret, but it reveals the wallet's whole history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPublic {
    pub family: Family,
    pub chain: Chain,
    pub account: u32,
    pub fingerprint: Fingerprint,
    pub xpub: Xpub,
}

impl AccountPublic {
    /// `m/<purpose>'/<coin>'/<account>'`, the key origin in every descriptor and PSBT.
    pub fn origin(&self) -> DerivationPath {
        account_path(self.family, self.chain, self.account).expect("account checked on construction")
    }

    /// The descriptor of one branch: 0 receives, 1 is change.
    pub fn descriptor(&self, change: u32) -> String {
        let origin = self.origin().to_string();
        let key = format!("[{}/{}]{}/{change}/*", self.fingerprint, origin.trim_start_matches("m/"), self.xpub);
        let body = match self.family {
            Family::Segwit => format!("wpkh({key})"),
            Family::Taproot => format!("tr({key})"),
        };
        let sum = descriptor_checksum(&body).expect("descriptors use only checksum characters");
        format!("{body}#{sum}")
    }

    /// The key at `<change>/<index>` below the account, both unhardened.
    pub fn key_at<C: Verification>(&self, secp: &Secp256k1<C>, change: u32, index: u32) -> Result<CompressedPublicKey> {
        if change > 1 || index >= HARDENED {
            return Err(bad(format!("{change}/{index} is not a receive or change index")));
        }
        let child = self
            .xpub
            .derive_pub(secp, &[ChildNumber::Normal { index: change }, ChildNumber::Normal { index }])
            .map_err(|e| bad(format!("bip32: {e}")))?;
        Ok(CompressedPublicKey(child.public_key))
    }

    /// The output script this wallet pays to at `<change>/<index>`.
    pub fn script_at<C: Verification>(&self, secp: &Secp256k1<C>, change: u32, index: u32) -> Result<ScriptBuf> {
        let key = self.key_at(secp, change, index)?;
        Ok(match self.family {
            Family::Segwit => ScriptBuf::new_p2wpkh(&key.wpubkey_hash()),
            Family::Taproot => ScriptBuf::new_p2tr(secp, UntweakedPublicKey::from(key.0), None),
        })
    }

    /// `<change>/<index>` when `path` is this account's origin followed by those two levels, unhardened.
    pub fn relative(&self, path: &DerivationPath) -> Option<(u32, u32)> {
        let origin = self.origin();
        let levels: Vec<ChildNumber> = path.into_iter().copied().collect();
        let (head, tail) = levels.split_at_checked(origin.len())?;
        if head != origin.as_ref() {
            return None;
        }
        match tail {
            [ChildNumber::Normal { index: c }, ChildNumber::Normal { index: i }] if *c <= 1 => Some((*c, *i)),
            _ => None,
        }
    }
}

const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(symbols: &[u64]) -> u64 {
    const GENERATOR: [u64; 5] = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];
    let mut chk = 1u64;
    for value in symbols {
        let top = chk >> 35;
        chk = ((chk & 0x7ffffffff) << 5) ^ value;
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// The BIP380 descriptor checksum, ported from the BIP's own Python. `None` for a character it can't encode.
pub fn descriptor_checksum(desc: &str) -> Option<String> {
    let mut symbols = Vec::new();
    let mut groups = Vec::new();
    for c in desc.chars() {
        let v = INPUT_CHARSET.find(c)? as u64;
        symbols.push(v & 31);
        groups.push(v >> 5);
        if groups.len() == 3 {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.clear();
        }
    }
    match groups.as_slice() {
        [g] => symbols.push(*g),
        [g0, g1] => symbols.push(g0 * 3 + g1),
        _ => {}
    }
    symbols.extend([0; 8]);
    let sum = polymod(&symbols) ^ 1;
    Some((0..8).map(|i| CHECKSUM_CHARSET[((sum >> (5 * (7 - i))) & 31) as usize] as char).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::base58;
    use bitcoin::{Address, PrivateKey};

    // Every expected value below is from bitcoin/bips at 927b6de9915c (2026-10-02): BIP84's and BIP86's
    // test vectors and BIP380's checksum vector. Not from a crate's documentation.
    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn seed() -> crate::hd::Seed {
        crate::hd::Seed::from_mnemonic(ABANDON, "").unwrap()
    }

    fn account(family: Family) -> (AccountSecret, AccountPublic) {
        let secp = Secp256k1::new();
        let s = seed();
        let (secret, fingerprint) =
            AccountSecret::from_seed(&secp, s.as_secret(), family, Chain::Main, 0).unwrap();
        let public = AccountPublic { family, chain: Chain::Main, account: 0, fingerprint, xpub: secret.xpub(&secp) };
        (secret, public)
    }

    /// The key bytes of an extended key, without its four version bytes, so zpub and xpub compare.
    fn key_data(s: &str) -> Vec<u8> {
        base58::decode_check(s).unwrap()[4..].to_vec()
    }

    #[test]
    fn bip84_published_vectors_reproduce_keys_and_addresses() {
        let secp = Secp256k1::new();
        let (secret, public) = account(Family::Segwit);
        // BIP84 writes its keys with SLIP-132 version bytes; the key data is what has to agree.
        assert_eq!(
            key_data(&secret.encode()),
            key_data("zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE")
        );
        assert_eq!(
            key_data(&public.xpub.to_string()),
            key_data("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
        );
        for (change, index, wif, pubkey, address) in [
            (0, 0, "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
             "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            (0, 1, "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy",
             "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
            (1, 0, "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF",
             "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"),
        ] {
            let key = public.key_at(&secp, change, index).unwrap();
            assert_eq!(key.to_string(), pubkey, "{change}/{index}");
            let child = secret.xprv().derive_priv(&secp, &[ChildNumber::Normal { index: change }, ChildNumber::Normal { index }]).unwrap();
            assert_eq!(PrivateKey::new(child.private_key, Network::Bitcoin).to_wif(), wif, "{change}/{index}");
            let script = public.script_at(&secp, change, index).unwrap();
            assert_eq!(Address::from_script(&script, Network::Bitcoin).unwrap().to_string(), address);
        }
    }

    #[test]
    fn bip86_published_vectors_reproduce_keys_and_addresses() {
        let secp = Secp256k1::new();
        let (secret, public) = account(Family::Taproot);
        assert_eq!(
            secret.encode().as_str(),
            "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk"
        );
        assert_eq!(
            public.xpub.to_string(),
            "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
        );
        for (change, index, internal, script_hex, address) in [
            (0, 0, "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
             "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
             "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
            (0, 1, "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
             "5120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
             "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"),
            (1, 0, "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
             "5120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
             "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"),
        ] {
            let key = public.key_at(&secp, change, index).unwrap();
            assert_eq!(UntweakedPublicKey::from(key.0).to_string(), internal, "{change}/{index}");
            let script = public.script_at(&secp, change, index).unwrap();
            assert_eq!(hex::encode(script.as_bytes()), script_hex, "{change}/{index}");
            assert_eq!(Address::from_script(&script, Network::Bitcoin).unwrap().to_string(), address);
        }
    }

    #[test]
    fn the_descriptor_checksum_matches_bip380() {
        assert_eq!(descriptor_checksum("raw(deadbeef)").unwrap(), "89f8spxm");
        assert!(descriptor_checksum("raw(Ü)").is_none());
        // A changed payload changes the checksum.
        assert_ne!(descriptor_checksum("raw(deedbeef)").unwrap(), "89f8spxm");
    }

    #[test]
    fn descriptors_carry_the_key_origin_and_a_valid_checksum() {
        let (_, public) = account(Family::Segwit);
        let d = public.descriptor(0);
        let fp = public.fingerprint.to_string();
        assert!(d.starts_with(&format!("wpkh([{fp}/84'/0'/0']xpub")), "{d}");
        assert!(d.contains("/0/*)#"), "{d}");
        let (body, sum) = d.split_once('#').unwrap();
        assert_eq!(descriptor_checksum(body).unwrap(), sum);
        assert!(public.descriptor(1).contains("/1/*)#"));
        let (_, tap) = account(Family::Taproot);
        assert!(tap.descriptor(0).starts_with(&format!("tr([{fp}/86'/0'/0']xpub")));
    }

    #[test]
    fn a_test_chain_uses_coin_type_one_and_never_signs_for_mainnet() {
        let secp = Secp256k1::new();
        let s = seed();
        let (secret, fp) = AccountSecret::from_seed(&secp, s.as_secret(), Family::Segwit, Chain::Test, 0).unwrap();
        let public = AccountPublic { family: Family::Segwit, chain: Chain::Test, account: 0, fingerprint: fp, xpub: secret.xpub(&secp) };
        assert!(public.descriptor(0).contains("/84'/1'/0']tpub"), "{}", public.descriptor(0));
        assert_eq!(Chain::Test.network("signet").unwrap(), Network::Signet);
        assert_eq!(Chain::Test.network("regtest").unwrap(), Network::Regtest);
        assert!(Chain::Test.network("bitcoin").is_err());
        assert!(Chain::Main.network("signet").is_err());
        assert!(Chain::Main.network("litecoin").is_err());
    }

    #[test]
    fn only_this_familys_account_paths_are_accepted() {
        assert_eq!(parse_account_path("m/84'/1'/3'", Family::Segwit, Chain::Test).unwrap(), 3);
        assert_eq!(parse_account_path("m/86h/0h/0h", Family::Taproot, Chain::Main).unwrap(), 0);
        for p in ["m/84'/0'/0'", "m/86'/1'/0'", "m/44'/1'/0'", "m/84'/1'/0", "m/84'/1'/0'/0", "m/84'/1'", "84'/1'/0'"] {
            assert!(parse_account_path(p, Family::Segwit, Chain::Test).is_err(), "{p}");
        }
    }

    #[test]
    fn a_path_is_relative_only_below_this_account() {
        let (_, public) = account(Family::Segwit);
        let p = |s: &str| DerivationPath::from_str(s).unwrap();
        assert_eq!(public.relative(&p("m/84'/0'/0'/1/7")), Some((1, 7)));
        for other in ["m/84'/0'/1'/0/0", "m/84'/0'/0'/2/0", "m/84'/0'/0'/0'/0", "m/84'/0'/0'/0", "m/84'/0'/0'/0/0/0", "m/86'/0'/0'/0/0"] {
            assert_eq!(public.relative(&p(other)), None, "{other}");
        }
    }

    #[test]
    fn a_stored_account_key_must_be_an_account_key_of_this_chain() {
        let (secret, _) = account(Family::Segwit);
        let encoded = secret.encode();
        assert!(AccountSecret::decode(&encoded, Chain::Main).is_ok());
        assert!(AccountSecret::decode(&encoded, Chain::Test).is_err());
        // The BIP86 root key, depth 0, is refused where an account key belongs.
        let root = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
        assert!(AccountSecret::decode(root, Chain::Main).is_err());
    }
}
