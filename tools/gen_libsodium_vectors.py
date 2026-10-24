"""Vectors from libsodium itself, the library Muster's room identity runs on
(module/src/crypto/curve25519.nim). The Rust identity must agree with every one.

    python3 -I tools/gen_libsodium_vectors.py > rust-lib/tests/vectors/libsodium.json
"""
import ctypes, ctypes.util, json, hashlib, hmac

so = ctypes.CDLL(ctypes.util.find_library("sodium") or "libsodium.so.23")
assert so.sodium_init() >= 0
B = ctypes.c_ubyte

def buf(n): return (B * n)()
def hx(b): return bytes(b).hex()

out = []
for i, msg in enumerate([b"", b"muster.event.author.v1", bytes(range(200))]):
    seed = hashlib.sha256(b"signer-vector-%d" % i).digest()
    pk, sk = buf(32), buf(64)
    assert so.crypto_sign_seed_keypair(pk, sk, (B * 32)(*seed)) == 0
    sig = buf(64)
    m = (B * max(len(msg), 1))(*msg)
    assert so.crypto_sign_detached(sig, None, m, ctypes.c_ulonglong(len(msg)), sk) == 0
    xpk, xsk = buf(32), buf(32)
    assert so.crypto_sign_ed25519_pk_to_curve25519(xpk, pk) == 0
    assert so.crypto_sign_ed25519_sk_to_curve25519(xsk, sk) == 0
    plain = b"epoch grant %d" % i
    sealed = buf(len(plain) + 48)
    assert so.crypto_box_seal(sealed, (B * len(plain))(*plain), ctypes.c_ulonglong(len(plain)), xpk) == 0
    info = b"founding-key-info-%d" % i
    out.append({
        "seed": seed.hex(), "edPk": hx(pk), "msg": msg.hex(), "sig": hx(sig),
        "xPk": hx(xpk), "xSk": hx(xsk), "plain": plain.hex(), "sealed": hx(sealed),
        "info": info.hex(), "derivedSecret": hmac.new(seed, info, hashlib.sha256).hexdigest(),
    })
print(json.dumps(out, indent=1))
