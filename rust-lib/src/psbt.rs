//! Bitcoin PSBTs: what one does, in the keystore's own words, and its signatures.
//! Pure: the keystore passes in the account, and its key only when signing.

use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv};
use bitcoin::consensus::Encodable;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::psbt::{self as bpsbt, GetKey, GetKeyError, KeyRequest, Psbt};
use bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use bitcoin::{Address, Amount, EcdsaSighashType, Network, PrivateKey, ScriptBuf, TapSighashType, TxIn, TxOut};

use crate::btc::{self, AccountPublic, AccountSecret, Family};
use crate::keystore::KeystoreError;

type Result<T> = std::result::Result<T, KeystoreError>;

fn bad(msg: impl Into<String>) -> KeystoreError {
    KeystoreError::InvalidParams(format!("psbt: {}", msg.into()))
}

/// A PSBT the keystore has read and accepts to sign, and what it found in it.
#[derive(Debug)]
pub struct Checked {
    /// What the signer shows, verbatim; the first line names the network and the wallet.
    pub lines: Vec<String>,
    /// The bytes the approval commitment covers: the transaction and what the lines say about it.
    pub canonical: Vec<u8>,
    pub fee: Amount,
}

pub fn parse(s: &str) -> Result<Psbt> {
    Psbt::from_str(s.trim()).map_err(|e| bad(e.to_string()))
}

/// Read a PSBT against one account, refusing anything this wallet would not sign.
pub fn check<C: Verification>(
    secp: &Secp256k1<C>,
    acct: &AccountPublic,
    network: Network,
    wallet: &str,
    psbt: &Psbt,
) -> Result<Checked> {
    let tx = &psbt.unsigned_tx;
    if tx.input.is_empty() || tx.output.is_empty() {
        return Err(bad("a transaction needs inputs and outputs"));
    }
    // A coin spent twice would be counted twice in the fee shown.
    let mut spent = std::collections::BTreeSet::new();
    if !tx.input.iter().all(|i| spent.insert(i.previous_output)) {
        return Err(bad("a coin is spent twice"));
    }
    let mut canonical = b"psbt\n".to_vec();
    canonical.extend_from_slice(network.to_core_arg().as_bytes());
    canonical.push(b'\n');
    tx.consensus_encode(&mut canonical).expect("writing to a Vec cannot fail");

    let mut total_in = Amount::ZERO;
    let mut witness = 0usize;
    let mut rbf = false;
    for (i, (txin, input)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
        refuse_unsignable(i, input)?;
        let prev = previous_output(i, acct.family, txin, input)?;
        check_sighash(i, acct.family, input)?;
        let (change, index) = owned_input(secp, acct, i, input, &prev.script_pubkey)?;
        total_in = total_in.checked_add(prev.value).ok_or_else(|| bad("input amounts overflow"))?;
        // Largest signature each can carry: DER plus sighash byte, or 64 bytes of Schnorr.
        witness += match acct.family {
            Family::Segwit => 1 + 1 + 73 + 1 + 33,
            Family::Taproot => 1 + 1 + 64 + usize::from(input.sighash_type.is_some()),
        };
        rbf |= txin.sequence.is_rbf();
        canonical.extend_from_slice(&prev.value.to_sat().to_le_bytes());
        prev.script_pubkey.consensus_encode(&mut canonical).expect("writing to a Vec cannot fail");
        canonical.extend_from_slice(&change.to_le_bytes());
        canonical.extend_from_slice(&index.to_le_bytes());
        canonical.push(input.sighash_type.map_or(0xff, |t| t.to_u32() as u8));
    }

    let origin = acct.origin();
    let mut total_out = Amount::ZERO;
    let mut out_lines = Vec::new();
    for (txout, output) in tx.output.iter().zip(&psbt.outputs) {
        total_out = total_out.checked_add(txout.value).ok_or_else(|| bad("output amounts overflow"))?;
        match owned_output(secp, acct, output, &txout.script_pubkey) {
            Some((change, index)) => {
                let what = if change == 1 { "Change" } else { "Receive" };
                out_lines.push(format!(
                    "{what} {} BTC back to this wallet (m/{}/{change}/{index}, checked)",
                    btc_amount(txout.value),
                    origin.to_string().trim_start_matches("m/")
                ));
                canonical.push(1);
                canonical.extend_from_slice(&change.to_le_bytes());
                canonical.extend_from_slice(&index.to_le_bytes());
            }
            None => {
                out_lines.push(describe_payment(txout, network));
                canonical.push(0);
            }
        }
    }
    let fee = total_in.checked_sub(total_out).ok_or_else(|| bad("the outputs spend more than the inputs hold"))?;

    // The signed size, at the largest each signature can be, so the rate shown is never above the real one.
    let weight = tx.base_size() * 4 + 2 + witness;
    let vsize = weight.div_ceil(4) as u64;
    let tenths = (fee.to_sat() * 10 + vsize / 2) / vsize;
    let n = tx.input.len();

    let mut lines = vec![format!(
        "Bitcoin {} · wallet {wallet}, {}, account {}",
        btc::network_name(network),
        acct.family.describe(),
        acct.account
    )];
    lines.extend(out_lines);
    lines.push(format!(
        "Fee {} sats, about {}.{} sat/vB, computed from the inputs",
        grouped(fee.to_sat()),
        tenths / 10,
        tenths % 10
    ));
    lines.push(format!(
        "Spends {n} coin{} worth {} BTC{}",
        if n == 1 { "" } else { "s" },
        btc_amount(total_in),
        if rbf { " · replaceable (RBF)" } else { "" }
    ));
    Ok(Checked { lines, canonical, fee })
}

/// Sign every input with this account's key, then insist each one carries its signature.
pub fn sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    acct: &AccountPublic,
    secret: &AccountSecret,
    psbt: &mut Psbt,
) -> Result<()> {
    let keys = AccountKeys { fingerprint: acct.fingerprint, origin: acct.origin(), xprv: secret.xprv() };
    psbt.sign(&keys, secp)
        .map_err(|(_, errors)| KeystoreError::Signing(format!("psbt: {errors:?}")))?;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let signed = match acct.family {
            Family::Segwit => !input.partial_sigs.is_empty(),
            Family::Taproot => input.tap_key_sig.is_some(),
        };
        if !signed {
            return Err(KeystoreError::Signing(format!("psbt: input {i} was not signed")));
        }
    }
    Ok(())
}

/// rust-bitcoin's own lookup for an `Xpriv` matches only a master key or the level below,
/// so this maps a key origin under the account onto the account key.
struct AccountKeys<'a> {
    fingerprint: Fingerprint,
    origin: DerivationPath,
    xprv: &'a Xpriv,
}

impl GetKey for AccountKeys<'_> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(&self, request: KeyRequest, secp: &Secp256k1<C>) -> std::result::Result<Option<PrivateKey>, Self::Error> {
        let KeyRequest::Bip32((fingerprint, path)) = request else { return Ok(None) };
        if fingerprint != self.fingerprint {
            return Ok(None);
        }
        let levels: Vec<ChildNumber> = path.into_iter().copied().collect();
        let Some(rest) = levels.strip_prefix(self.origin.as_ref()) else { return Ok(None) };
        Ok(Some(self.xprv.derive_priv(secp, &rest)?.to_priv()))
    }
}

/// Already signed, a script path, or a multi-key script: none of it is a single-key spend this wallet signs.
fn refuse_unsignable(i: usize, input: &bpsbt::Input) -> Result<()> {
    if !input.partial_sigs.is_empty()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
        || input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
    {
        return Err(bad(format!("input {i} is already signed")));
    }
    if !input.tap_scripts.is_empty() || input.tap_merkle_root.is_some() {
        return Err(bad(format!("input {i} spends a taproot script path, which this wallet doesn't sign")));
    }
    if input.redeem_script.is_some() || input.witness_script.is_some() {
        return Err(bad(format!("input {i} spends a script, not a single key")));
    }
    Ok(())
}

/// The output an input spends, checked against its whole previous transaction where there is one.
fn previous_output(i: usize, family: Family, txin: &TxIn, input: &bpsbt::Input) -> Result<TxOut> {
    let from_tx = match &input.non_witness_utxo {
        Some(prev) => {
            if prev.compute_txid() != txin.previous_output.txid {
                return Err(bad(format!("input {i}'s previous transaction is not the one it spends")));
            }
            let out = prev.output.get(txin.previous_output.vout as usize).cloned();
            Some(out.ok_or_else(|| bad(format!("input {i} spends an output its previous transaction doesn't have")))?)
        }
        None => None,
    };
    match (family, from_tx, &input.witness_utxo) {
        // A segwit v0 signature commits only to its own input's amount: the 2020 fee attack.
        (Family::Segwit, None, _) => Err(bad(format!(
            "input {i} has no previous transaction, which a native segwit input needs so its amount can be checked"
        ))),
        (_, Some(full), Some(w)) if full != *w => {
            Err(bad(format!("input {i}'s amount disagrees with its previous transaction")))
        }
        (_, Some(full), _) => Ok(full),
        (Family::Taproot, None, Some(w)) => Ok(w.clone()),
        (Family::Taproot, None, None) => Err(bad(format!("input {i} has no previous output"))),
    }
}

fn check_sighash(i: usize, family: Family, input: &bpsbt::Input) -> Result<()> {
    let Some(ty) = input.sighash_type else { return Ok(()) };
    let ok = match family {
        Family::Segwit => matches!(ty.ecdsa_hash_ty(), Ok(EcdsaSighashType::All)),
        Family::Taproot => matches!(ty.taproot_hash_ty(), Ok(TapSighashType::Default | TapSighashType::All)),
    };
    if ok {
        Ok(())
    } else {
        Err(bad(format!("input {i} asks for sighash {ty}; this wallet signs only ALL")))
    }
}

/// `<change>/<index>` of the one key of this account an input names, proved by deriving it.
fn owned_input<C: Verification>(
    secp: &Secp256k1<C>,
    acct: &AccountPublic,
    i: usize,
    input: &bpsbt::Input,
    script: &ScriptBuf,
) -> Result<(u32, u32)> {
    let mut found = None;
    let mut claim = |path: &DerivationPath| -> Result<(u32, u32)> {
        let at = acct.relative(path).ok_or_else(|| bad(format!("input {i} names a path outside this wallet's account: {path}")))?;
        if found.replace(at).is_some() {
            return Err(bad(format!("input {i} names this wallet's keys twice")));
        }
        Ok(at)
    };
    match acct.family {
        Family::Segwit => {
            for (pk, (fp, path)) in &input.bip32_derivation {
                if *fp != acct.fingerprint {
                    continue;
                }
                let (c, idx) = claim(path)?;
                if acct.key_at(secp, c, idx)?.0 != *pk {
                    return Err(bad(format!("input {i}'s key is not the one at {path}")));
                }
            }
        }
        Family::Taproot => {
            let internal = input.tap_internal_key;
            for (xonly, (leaves, (fp, path))) in &input.tap_key_origins {
                if *fp != acct.fingerprint {
                    continue;
                }
                if !leaves.is_empty() {
                    return Err(bad(format!("input {i} asks for a script-path signature")));
                }
                let (c, idx) = claim(path)?;
                let key = UntweakedPublicKey::from(acct.key_at(secp, c, idx)?.0);
                if key != *xonly || Some(key) != internal {
                    return Err(bad(format!("input {i}'s key is not the one at {path}")));
                }
            }
        }
    }
    let (c, idx) = found.ok_or_else(|| bad(format!("input {i} is not this wallet's to sign")))?;
    if acct.script_at(secp, c, idx)? != *script {
        return Err(bad(format!("input {i} spends a script this wallet's key doesn't control")));
    }
    Ok((c, idx))
}

/// An output is this wallet's only if deriving the path it claims gives its script. Change is checked, not trusted.
fn owned_output<C: Verification>(
    secp: &Secp256k1<C>,
    acct: &AccountPublic,
    output: &bpsbt::Output,
    script: &ScriptBuf,
) -> Option<(u32, u32)> {
    let claimed: Vec<(u32, u32)> = match acct.family {
        Family::Segwit => output
            .bip32_derivation
            .values()
            .filter(|(fp, _)| *fp == acct.fingerprint)
            .filter_map(|(_, path)| acct.relative(path))
            .collect(),
        Family::Taproot => output
            .tap_key_origins
            .values()
            .filter(|(leaves, (fp, _))| leaves.is_empty() && *fp == acct.fingerprint)
            .filter_map(|(_, (_, path))| acct.relative(path))
            .collect(),
    };
    claimed.into_iter().find(|(c, i)| acct.script_at(secp, *c, *i).is_ok_and(|s| s == *script))
}

fn describe_payment(out: &TxOut, network: Network) -> String {
    let amount = btc_amount(out.value);
    if out.script_pubkey.is_op_return() {
        return format!("Data output (OP_RETURN, {} bytes) carrying {amount} BTC", out.script_pubkey.len());
    }
    match Address::from_script(&out.script_pubkey, network) {
        Ok(addr) => format!("Send {amount} BTC to {addr}"),
        Err(_) => format!("Send {amount} BTC to a script with no address: {}", hex::encode(out.script_pubkey.as_bytes())),
    }
}

fn btc_amount(a: Amount) -> String {
    let sats = a.to_sat();
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::btc::{AccountSecret, Chain};
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::psbt::PsbtSighashType;
    use bitcoin::secp256k1::{ecdsa, schnorr, Message};
    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, Sequence, Transaction, Witness};

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const ZOO: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

    pub(crate) fn account(phrase: &str, family: Family) -> (AccountSecret, AccountPublic) {
        let secp = Secp256k1::new();
        let seed = crate::hd::Seed::from_mnemonic(phrase, "").unwrap();
        let (secret, fingerprint) = AccountSecret::from_seed(&secp, seed.as_secret(), family, Chain::Test, 0).unwrap();
        let public = AccountPublic { family, chain: Chain::Test, account: 0, fingerprint, xpub: secret.xpub(&secp) };
        (secret, public)
    }

    fn funding(script: ScriptBuf, sats: u64, salt: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(salt),
            input: vec![TxIn { previous_output: OutPoint::null(), ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(sats), script_pubkey: script }],
        }
    }

    fn mark_input(acct: &AccountPublic, input: &mut bpsbt::Input, change: u32, index: u32) {
        let secp = Secp256k1::new();
        let key = acct.key_at(&secp, change, index).unwrap();
        let path = acct.origin().extend([ChildNumber::Normal { index: change }, ChildNumber::Normal { index }]);
        match acct.family {
            Family::Segwit => {
                input.bip32_derivation.insert(key.0, (acct.fingerprint, path));
            }
            Family::Taproot => {
                let x = UntweakedPublicKey::from(key.0);
                input.tap_internal_key = Some(x);
                input.tap_key_origins.insert(x, (vec![], (acct.fingerprint, path)));
            }
        }
    }

    fn mark_output(acct: &AccountPublic, output: &mut bpsbt::Output, change: u32, index: u32) {
        let secp = Secp256k1::new();
        let key = acct.key_at(&secp, change, index).unwrap();
        let path = acct.origin().extend([ChildNumber::Normal { index: change }, ChildNumber::Normal { index }]);
        match acct.family {
            Family::Segwit => {
                output.bip32_derivation.insert(key.0, (acct.fingerprint, path));
            }
            Family::Taproot => {
                let x = UntweakedPublicKey::from(key.0);
                output.tap_internal_key = Some(x);
                output.tap_key_origins.insert(x, (vec![], (acct.fingerprint, path)));
            }
        }
    }

    /// Two coins of ours (0/0 and 0/1), a payment to someone else, and change to 1/0, as BDK builds it.
    pub(crate) fn sample(acct: &AccountPublic) -> Psbt {
        let secp = Secp256k1::new();
        let (_, other) = account(ZOO, acct.family);
        let prev_a = funding(acct.script_at(&secp, 0, 0).unwrap(), 100_000, 1);
        let prev_b = funding(acct.script_at(&secp, 0, 1).unwrap(), 50_000, 2);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(150),
            input: [&prev_a, &prev_b]
                .iter()
                .map(|p| TxIn {
                    previous_output: OutPoint { txid: p.compute_txid(), vout: 0 },
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    script_sig: ScriptBuf::new(),
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![
                TxOut { value: Amount::from_sat(120_000), script_pubkey: other.script_at(&secp, 0, 0).unwrap() },
                TxOut { value: Amount::from_sat(28_810), script_pubkey: acct.script_at(&secp, 1, 0).unwrap() },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (k, (prev, index)) in [(&prev_a, 0), (&prev_b, 1)].into_iter().enumerate() {
            psbt.inputs[k].witness_utxo = Some(prev.output[0].clone());
            if acct.family == Family::Segwit {
                psbt.inputs[k].non_witness_utxo = Some(prev.clone());
            }
            mark_input(acct, &mut psbt.inputs[k], 0, index);
        }
        mark_output(acct, &mut psbt.outputs[1], 1, 0);
        psbt
    }

    fn checked(acct: &AccountPublic, psbt: &Psbt) -> Result<Checked> {
        check(&Secp256k1::new(), acct, Network::Regtest, "\"Savings\"", psbt)
    }

    #[test]
    fn the_lines_name_the_payment_the_change_and_the_fee_the_keystore_computed() {
        for family in [Family::Segwit, Family::Taproot] {
            let (_, acct) = account(ABANDON, family);
            let psbt = sample(&acct);
            let c = checked(&acct, &psbt).unwrap();
            assert_eq!(c.fee, psbt.fee().unwrap(), "{family:?}");
            assert_eq!(c.fee.to_sat(), 1_190);
            let all = c.lines.join("\n");
            let purpose = family.purpose();
            assert!(all.starts_with(&format!("Bitcoin regtest · wallet \"Savings\", {}, account 0", family.describe())), "{all}");
            assert!(all.contains("Send 0.00120000 BTC to bcrt1"), "{all}");
            assert!(all.contains(&format!("Change 0.00028810 BTC back to this wallet (m/{purpose}'/1'/0'/1/0, checked)")), "{all}");
            assert!(all.contains("Fee 1,190 sats, about "), "{all}");
            assert!(all.contains("Spends 2 coins worth 0.00150000 BTC · replaceable (RBF)"), "{all}");
        }
    }

    #[test]
    fn change_that_pays_a_key_outside_the_wallet_is_shown_as_a_send() {
        let secp = Secp256k1::new();
        let (_, acct) = account(ABANDON, Family::Segwit);
        let (_, other) = account(ZOO, Family::Segwit);
        let mut psbt = sample(&acct);
        // The change output still claims 1/0, but its script pays someone else.
        psbt.unsigned_tx.output[1].script_pubkey = other.script_at(&secp, 1, 0).unwrap();
        let all = checked(&acct, &psbt).unwrap().lines.join("\n");
        assert!(!all.contains("back to this wallet"), "{all}");
        assert_eq!(all.matches("Send ").count(), 2, "{all}");
    }

    #[test]
    fn a_false_input_amount_is_refused_before_anything_is_shown() {
        let (_, acct) = account(ABANDON, Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(10_000);
        let e = checked(&acct, &psbt).unwrap_err().to_string();
        assert!(e.contains("amount disagrees"), "{e}");
    }

    #[test]
    fn a_native_segwit_input_without_its_previous_transaction_is_refused() {
        let (_, acct) = account(ABANDON, Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.inputs[1].non_witness_utxo = None;
        let e = checked(&acct, &psbt).unwrap_err().to_string();
        assert!(e.contains("no previous transaction"), "{e}");
        // A previous transaction that isn't the one spent is refused too.
        let mut psbt = sample(&acct);
        psbt.inputs[1].non_witness_utxo = psbt.inputs[0].non_witness_utxo.clone();
        assert!(checked(&acct, &psbt).is_err());
    }

    #[test]
    fn a_foreign_input_is_refused() {
        let (_, acct) = account(ABANDON, Family::Segwit);
        let (_, other) = account(ZOO, Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.inputs[1].bip32_derivation.clear();
        let e = checked(&acct, &psbt).unwrap_err().to_string();
        assert!(e.contains("not this wallet's"), "{e}");
        // Nor can another wallet sign this one's PSBT.
        assert!(checked(&other, &sample(&acct)).is_err());
    }

    #[test]
    fn a_key_claimed_at_a_path_must_be_the_key_at_that_path() {
        let (_, acct) = account(ABANDON, Family::Segwit);
        let mut psbt = sample(&acct);
        let (_, source) = psbt.inputs[0].bip32_derivation.pop_first().unwrap();
        let wrong = acct.key_at(&Secp256k1::new(), 0, 5).unwrap();
        psbt.inputs[0].bip32_derivation.insert(wrong.0, source);
        assert!(checked(&acct, &psbt).is_err());
    }

    #[test]
    fn a_sighash_other_than_all_is_refused() {
        for family in [Family::Segwit, Family::Taproot] {
            let (_, acct) = account(ABANDON, family);
            let mut psbt = sample(&acct);
            psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::SinglePlusAnyoneCanPay));
            assert!(checked(&acct, &psbt).is_err(), "{family:?}");
            let mut psbt = sample(&acct);
            psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
            assert!(checked(&acct, &psbt).is_ok(), "{family:?}");
        }
    }

    #[test]
    fn script_paths_and_signed_inputs_are_refused() {
        let (_, acct) = account(ABANDON, Family::Taproot);
        let mut psbt = sample(&acct);
        let (x, (_, source)) = psbt.inputs[0].tap_key_origins.pop_first().unwrap();
        psbt.inputs[0].tap_key_origins.insert(x, (vec![bitcoin::TapLeafHash::all_zeros()], source));
        assert!(checked(&acct, &psbt).is_err());
        let mut psbt = sample(&acct);
        psbt.inputs[1].final_script_witness = Some(Witness::new());
        assert!(checked(&acct, &psbt).is_err());
    }

    #[test]
    fn a_coin_spent_twice_is_refused() {
        let (_, acct) = account(ABANDON, Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.unsigned_tx.input[1].previous_output = psbt.unsigned_tx.input[0].previous_output;
        psbt.inputs[1] = psbt.inputs[0].clone();
        let e = checked(&acct, &psbt).unwrap_err().to_string();
        assert!(e.contains("spent twice"), "{e}");
    }

    #[test]
    fn outputs_spending_more_than_the_inputs_are_refused() {
        let (_, acct) = account(ABANDON, Family::Taproot);
        let mut psbt = sample(&acct);
        psbt.unsigned_tx.output[0].value = Amount::from_sat(200_000);
        let e = checked(&acct, &psbt).unwrap_err().to_string();
        assert!(e.contains("more than the inputs"), "{e}");
    }

    #[test]
    fn the_commitment_moves_with_anything_shown() {
        let (_, acct) = account(ABANDON, Family::Segwit);
        let base = checked(&acct, &sample(&acct)).unwrap().canonical;
        let mut psbt = sample(&acct);
        psbt.unsigned_tx.output[0].value = Amount::from_sat(119_999);
        assert_ne!(checked(&acct, &psbt).unwrap().canonical, base);
        // Change that stops being ours changes what is shown, so it changes the commitment too.
        let mut psbt = sample(&acct);
        psbt.outputs[1].bip32_derivation.clear();
        assert_ne!(checked(&acct, &psbt).unwrap().canonical, base);
        // A field nothing reads does not.
        let mut psbt = sample(&acct);
        psbt.inputs[0].proprietary.insert(
            bitcoin::psbt::raw::ProprietaryKey { prefix: b"x".to_vec(), subtype: 0, key: vec![] },
            vec![1],
        );
        assert_eq!(checked(&acct, &psbt).unwrap().canonical, base);
    }

    #[test]
    fn signatures_verify_against_the_sighash_computed_independently() {
        let secp = Secp256k1::new();
        for family in [Family::Segwit, Family::Taproot] {
            let (secret, acct) = account(ABANDON, family);
            let mut psbt = sample(&acct);
            sign(&secp, &acct, &secret, &mut psbt).unwrap();
            let prevouts: Vec<TxOut> = psbt.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
            let mut cache = SighashCache::new(&psbt.unsigned_tx);
            for (i, index) in [0u32, 1].into_iter().enumerate() {
                let key = acct.key_at(&secp, 0, index).unwrap();
                match family {
                    Family::Segwit => {
                        let sighash = cache
                            .p2wpkh_signature_hash(i, &prevouts[i].script_pubkey, prevouts[i].value, EcdsaSighashType::All)
                            .unwrap();
                        let sig = psbt.inputs[i].partial_sigs[&bitcoin::PublicKey::new(key.0)];
                        let msg = Message::from_digest(sighash.to_byte_array());
                        secp.verify_ecdsa(&msg, &sig.signature, &key.0).unwrap();
                        let _: &ecdsa::Signature = &sig.signature;
                    }
                    Family::Taproot => {
                        let sighash = cache
                            .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
                            .unwrap();
                        let sig = psbt.inputs[i].tap_key_sig.unwrap();
                        let internal = UntweakedPublicKey::from(key.0);
                        let (output_key, _) = bitcoin::key::TapTweak::tap_tweak(internal, &secp, None);
                        let msg = Message::from_digest(sighash.to_byte_array());
                        secp.verify_schnorr(&sig.signature, &msg, &output_key.to_x_only_public_key()).unwrap();
                        let _: &schnorr::Signature = &sig.signature;
                    }
                }
            }
        }
    }

    #[test]
    fn amounts_and_counts_read_as_people_write_them() {
        assert_eq!(btc_amount(Amount::from_sat(1_500_000)), "0.01500000");
        assert_eq!(btc_amount(Amount::from_sat(2_100_000_000_000_000)), "21000000.00000000");
        assert_eq!(grouped(2190), "2,190");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000_000), "1,000,000");
    }
}
