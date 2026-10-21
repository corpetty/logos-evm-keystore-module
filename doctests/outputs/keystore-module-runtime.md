# Running the Keystore Module Against logosctl

`logos-evm-keystore-module` is the keystore for the Logos multi-chain EVM
wallet: scrypt-encrypted vaults, BIP39/BIP32 HD derivation, and secp256k1
signing, built on [`alloy`](https://github.com/alloy-rs/alloy) and
[`eth-keystore`](https://crates.io/crates/eth-keystore). It does **no
networking** and private keys never cross the module boundary.

This doc-test exercises the module end-to-end through the headless `logosctl`
runtime — every step is **offline and deterministic**, so it needs no network
and reproduces in CI:

1. Build `logosctl` from its published flake.
2. Build this module's installable `.lgx` from its `#lgx` output.
3. Start a `logosctl` daemon and install the `.lgx` into its session.
4. Load `keystore_module`, name who holds its two
   roles with `configure`, and drive it: generate a mnemonic, import a known
   private key, and then **demonstrate that the CLI cannot make it sign
   anything** — signing requires a human approving through the dedicated
   signer UI.

**What you'll build:** This `keystore_module`, packaged as `.lgx`, installed into a `logosctl` session, and called through its daemon.

**What you'll learn:**

- How a Rust (rust-first cdylib) Logos module is packaged as an installable `.lgx`
- Why a module takes its configuration from a method call rather than from a file in its own data directory
- How to install it into a `logosctl` session and load it into the daemon
- Why a signature cannot be obtained from the CLI, and what refuses it
- How the keystore keeps private keys inside the module (only addresses and signed payloads come out)

## Prerequisites

- **Nix** with flakes enabled. Install from [nixos.org](https://nixos.org/download.html), then enable flakes:

```bash
mkdir -p ~/.config/nix
echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf
```

Verify: `nix flake --help >/dev/null 2>&1 && echo "Flakes enabled"`

- **A Linux or macOS machine.** Everything here is offline.

---

## Step 1: Build logosctl

`logosctl` is the headless frontend for `logos-liblogos` (it brings in the
whole module-runtime stack), and it installs `.lgx` packages too.

### 1.1 Build logosctl

```bash
nix build 'github:logos-co/logos-logoscore-cli#ctl' --out-link ./logos
```

### 1.2 Prove the CLI actually runs

```bash
logosctl --version
```

---

## Step 2: Build and install the keystore module

Build this module's `.lgx` from its flake's `#lgx` output, start a daemon,
and install the package into the daemon's session.

### 2.1 Build the module's .lgx

```bash
# From inside the clone this is simply: nix build '.#lgx'
nix build 'github:logos-co/logos-evm-keystore-module#lgx' -o keystore-lgx
```

```bash
ls keystore-lgx/*.lgx
```

### 2.2 Start the daemon

The session directory, `./session`, holds the daemon's config, its
installed modules and their data. `--detach` returns once the daemon
accepts commands.

```bash
logosctl daemon start --detach
```

### 2.3 Install the .lgx

A path ending in `.lgx` installs from disk, with no catalog involved. A
local build is unsigned, which the session's default policy accepts with
a warning. `-y` confirms, since there is no terminal to ask on.

```bash
logosctl install keystore-lgx/*.lgx -y
```

### 2.4 Build the custodian fixture

Account mutation is gated on a configured **custodian**. In production that is
`evm_keystore_ui`; here it is a small fixture module, so the gate can be exercised
from both sides headlessly. A fixture is a real caller with a real name — the
gate does not care what a module is *for*.

```bash
# From inside the clone this is simply:
nix build './doctests/custodian-probe#lgx' -o custodian-lgx
```

### 2.5 Install it

```bash
logosctl install custodian-lgx/*.lgx -y
```

### 2.6 Confirm the install

```bash
logosctl package ls
```

---

## Step 3: Drive the keystore

Load the module and call it. We use Foundry's well-known test key (account 0,
`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`). Note that `logosctl`'s `call`
auto-types a `0x…` argument as a number, so addresses are passed as **bare
hex** — the keystore accepts either form.

### 3.1 Load the module

```bash
logosctl module load keystore_module
```

### 3.2 Name the approver and the custodian

Configuration reaches this module through a **method call**, never through a file
dropped into its data directory: that directory belongs to the module instance and
may be sandboxed away from every other process, so nothing outside can count on
being able to write there — or on the directory existing yet.

`configure` is **total**: the document is the whole answer to who holds the
roles, and a role it does not name is held by nobody (an empty name admits no
caller). Until it is called the built-in defaults stand — `evm_signer_ui` approves,
`evm_keystore_ui` mutates, `signer_manager_module` asks for signatures — so a
deployment that configures nothing still works. Here the custodian is the fixture
instead, and the change takes effect on the next call: nothing is restarted. This
document names no manager, so from here on nothing may ask this keystore to sign.

It is **ungated for now**, which is a real and deliberate exposure: nothing stops a
caller naming *itself* custodian and then mutating the keystore — this very step is
the CLI writing that policy. Protecting the call is deferred, not refuted. The
refusals below are real, but they refuse a policy the same caller could have
written differently.

```bash
logosctl call keystore_module configure '{"approvers":"evm_signer_ui","custodians":"keystore_custodian"}'
```

### 3.3 Introspect the module

```bash
logosctl module show keystore_module
```

### 3.4 The keystore is a signer

The keystore implements `logos.signer/1`, the contract the signer manager binds every
signer module through. `signer_info` describes the kind of signer, not any account,
so it answers anyone: a keystore signs hashes, and the host collects a password.

```bash
logosctl call keystore_module signer_info
```

### 3.5 …and only the manager may ask it to sign

`sign` and `unlock` are Tier M, the configured manager's: the manager keeps which apps
an unlock covers, so anything reaching `sign` past it would sign inside an unlock it
was never granted. The CLI's host anchor is refused with the same string as every
other tier, and so is a listing of accounts, whose Bitcoin xpubs reveal a wallet's
history.

```bash
logosctl call keystore_module sign '{...}'
```

### 3.6 Load the custodian fixture

```bash
./logos/bin/logosctl --config-dir ./session module load keystore_custodian
```

### 3.7 The CLI cannot mutate the keystore

The CLI authenticates as the **host anchor** — one undifferentiated bag covering
the shells and every relayed token. Admitting it would make `logosctl call` a
legal way to import a key, so Tier D refuses it. The refusal string is identical
to Tier A's and Tier B's, so a caller cannot use the error text to work out which
tier it failed.

```bash
logosctl call keystore_module import_private_key <privkey> pw
```

### 3.8 …and it cannot derive an account either

HD derivation is account mutation, so it sits behind the same gate. It also opens a
vault whose blast radius is a whole wallet rather than one account — an `extkey`
group's stored key reaches every address under one BIP-44 account, past and future.
The refusal is byte-identical to the one above.

```bash
logosctl call keystore_module derive_next_account '{"groupPassword":"gp","password":"pw"}'
```

### 3.9 …but the ungated reads still work

The gate closed account *mutation*, not the module. A wallet must still be able to
show which accounts exist — that is exactly the line Tier D draws.

```bash
logosctl call keystore_module list_accounts
```

### 3.10 Generate a BIP-39 mnemonic, through the custodian

The other side of the refusal two steps up: the same Tier D method, from the module
`configure` just named custodian. It persists nothing, so what it proves is the
gate and only the gate.

```bash
logosctl call keystore_custodian mnemonic 12
```

### 3.11 Import a known private key

Import Foundry's account-0 private key under a passphrase. The module
returns only the **address** — the key stays inside the scrypt vault.

```bash
logosctl call keystore_custodian import_key <privkey> pw
```

### 3.12 List accounts

```bash
logosctl call keystore_module list_accounts
```

### 3.13 A key no recovery phrase covers needs an acknowledgement

`create_unrelated_account` is the **one** way to obtain a key generated from
randomness rather than derived from a phrase. There used to be a second,
`new_account`, which minted one silently on a keystore that looked empty — whether
that was safe rested on a directory scan being complete, and "is there live key
material anywhere under this store" is not decidable by inspection.

The acknowledgement is. Note who is refused here: the **custodian**, the one caller
Tier D admits. The acknowledgement is a property of the call, not of the caller, so
there is no identity that skips it.

```bash
logosctl call keystore_custodian create pw false
```

### 3.14 …and with it, the key lands

Same caller, same password, one argument different. The refusal above is not a
rate limit or a retry — the key does not exist until it is acknowledged.

```bash
logosctl call keystore_custodian create pw true
```

### 3.15 A file the keystore did not write is reported, not a wedge

Drop a `.DS_Store` into the keystore directory. The scan cannot explain it, and it
says so — but it no longer refuses anything: listing, creating and sweeping all
keep working, and the reported path is removable by name. When the scan was the
safety gate this was a brick, because anything it could not name might have been a
hidden derivation key.

This is the one step that reaches into the module's own directory, and it is not
configuration: it stands in for the operating system putting a file there, which no
method call can simulate. It is what the module has to survive, not how it is told
anything.

```bash
echo x > <module-data>/keystore/.DS_Store
logosctl call keystore_module list_accounts
logosctl call keystore_custodian remove .DS_Store
```

### 3.16 Name a wallet — and prove you hold one of its accounts

A derivation group has no name of its own to fall back on: what a UI shows is its
first account's address, and deleting that account moves it. `set_group_label`
gives it one. It is Tier D, so the CLI is refused and the custodian is not.

Tier D is not the whole story here. A name is the one string in this keystore that
an attacker chooses and a human reads — it is rendered *in place of* an address —
so setting one now also needs the vault password of **one of the wallet's own
accounts**. Holding an account is precisely the claim "this wallet is mine". The
*group* password is not accepted here: it proves you can make accounts, not that
you own the ones the header speaks for. Where the wallet has **no** accounts and
only a key, it is the credential — see the next step.

`get_group_labels` is **ungated**, and answers from its own document rather than
from the group record — so the name outlives the record and the key it belonged to,
which is exactly the row a UI has to name while asking whether to delete it. Two
wallets may carry one name: telling them apart is the reader's job, and refusing
the write would only stop it showing what the user actually did.

```bash
logosctl call keystore_module set_group_label '{"group":"<g>","label":"Cold storage"}'   # refused: Tier D
logosctl call keystore_custodian name_wallet <g> "Cold storage" <address> wrong-password # refused: password
logosctl call keystore_custodian name_wallet <g> "Cold storage" "" ""                    # refused: no account named
logosctl call keystore_custodian name_wallet <g> "Cold storage" <address> pw2            # written
logosctl call keystore_module get_group_labels
```

### 3.17 A wallet that can still mint accounts is named by its derivation key

"No accounts" is not "holds nothing". A wallet that keeps a derivation key and has
no accounts *yet* will have them, and they will be shown under whatever name is on
the header — so a name written here with no proof comes to stand over a real
account the moment one is derived. The exemption is therefore for a wallet that
holds **nothing**: no accounts *and* no key at either path, which is the same
precondition `remove_group` refuses on.

With a key and no accounts there is no account to hold, so what proves the name is
the thing that will mint them: the **derivation key's** own password. Clearing a
name still asks for nothing, and `forget_derivation` still takes no password — a
key you cannot open stays deletable.

```bash
logosctl call keystore_custodian delete <address> pw4          # the wallet now has no accounts
logosctl call keystore_custodian name_wallet <g> "Cold storage" "" ""              # refused: needs the key
logosctl call keystore_custodian name_wallet <g> "Cold storage" "" wrong-password  # refused: password
logosctl call keystore_custodian name_wallet <g> "Cold storage" "" gp4             # written
logosctl call keystore_custodian derive <g> gp4 pw4            # and now the name stands over an account
logosctl call keystore_module list_groups
```

### 3.18 Naming an account proves you hold that account

The same rule, one level down, and this is the sharper case: `set_label` writes the
string a wallet renders *instead of* an address in its account picker. Renaming
"Savings" to something a user would fund is exactly the attack, so setting a name
needs that account's own vault password.

**Clearing a name needs nothing.** It can only move the display back toward the raw
address, which is ground truth — it cannot impersonate anyone — and it is the one
way to strip a stale name off an account whose password is lost. Without that
exemption we would rebuild the wedge `forget_derivation` exists to avoid: a thing
you cannot open and therefore cannot manage.

The account below is Foundry's account 0, imported near the top of this run under
the password `pw`.

```bash
logosctl call keystore_custodian name_account <address> Treasury wrong-password  # refused
logosctl call keystore_custodian name_account <address> Treasury pw              # written
logosctl call keystore_custodian name_account <address> "  " nonsense            # cleared, no password
logosctl call keystore_module get_labels
```

### 3.19 A wallet with nothing left in it can finally be removed

A wallet is up to four things: a record in `groups.json`, a name in
`group-labels.json`, a derivation key, and its accounts. `forget_derivation`
removes the **key** and reports not-found when there is none — so a wallet that is
not derivable and holds no accounts had only a record, and nothing in this module
could take its row off the screen. `remove_group` is that method.

It removes the record and the name, and it **refuses while the wallet still holds
anything** — a derivation key (live or staged) or an account. So it is never a
second door to deleting a key, and because "holds nothing" is the precondition it
needs no password: there is nothing signable left for one to protect. The ladder
below is the whole cost, and it is the correct cost — every rung that is refused is
refused because a spendable key is still under that row.

```bash
logosctl call keystore_custodian name_wallet <g> "Old phone" <address> pw3
logosctl call keystore_module remove_group '{"group":"<g>"}'  # refused: Tier D
logosctl call keystore_custodian remove_wallet <g>            # refused: it still keeps a key
logosctl call keystore_custodian forget <g>
logosctl call keystore_custodian remove_wallet <g>            # refused: it still holds an account
logosctl call keystore_custodian delete <address> pw3
logosctl call keystore_custodian remove_wallet <g>            # the row goes
logosctl call keystore_module list_groups
```

### 3.20 Keeping the recovery phrase is the person's choice

Off unless asked for. `keepPhrase` keeps the phrase in a scrypt vault of its own, under
a password of its own, and the wallet names it. More wallets come from the kept phrase
without typing the words again, with that password: a taproot one, and an EVM one at
address index 5. The words go to the keys app alone (`show_phrase`, Tier D);
`forget_phrase` removes the vault with no password, and the wallets made from it stay.

```bash
logosctl call keystore_custodian bitcoin '{"phrase":"<words>","family":"bitcoin","chain":"test","password":"bpw","keepPhrase":{"password":"ppw"}}'
logosctl call keystore_custodian bitcoin '{"keptPhrase":"<p_…>","phrasePassword":"ppw","family":"bitcoin_taproot","chain":"test","password":"bpw"}'
logosctl call keystore_custodian evm '{"keptPhrase":"<p_…>","phrasePassword":"ppw","accountIndex":5,"password":"epw"}'
logosctl call keystore_module list_phrases
logosctl call keystore_module show_phrase '{"phrase":"<p_…>","password":"ppw"}'     # refused: Tier D
logosctl call keystore_custodian phrase '{"phrase":"<p_…>","password":"bpw"}'       # the wallet's password is not the phrase's
logosctl call keystore_custodian phrase '{"phrase":"<p_…>","password":"ppw"}'
logosctl call keystore_custodian forget_phrase '{"phrase":"<p_…>"}'
logosctl call keystore_module list_phrases
```

### 3.21 Ask the module who it thinks is calling

The CLI presents a host bootstrap anchor, so the keystore names it
`host` — honestly, and without inventing a module name. `core` and
`capability_module` share one token value under two keys, so an anchor
cannot be attributed to any particular party. That is the whole reason
the next two steps refuse: the caller is named, and is not admitted.

```bash
logosctl call keystore_module caller_identity
```

### 3.22 Request a signature from the CLI — refused

`request_approval` is Tier B: any **named module** may ask for a
signature. The CLI is not a named module, so it cannot even ask.

```bash
logosctl call keystore_module request_approval '{...intent...}'
```

### 3.23 Approve a signature from the CLI — refused

`approve` is Tier A: **only** the configured approver (`evm_signer_ui`) may
approve, and it must be a human doing it. There is no flag, token or
argument that makes this succeed from a shell — which is the property
this module exists to provide.

```bash
logosctl call keystore_module pending
```

### 3.24 Stop the daemon

```bash
logosctl daemon stop
```

### 3.25 Confirm the daemon has stopped

```bash
logosctl daemon status
```
