//! RFC 9180 HPKE Base-mode suites backed by `ring` and `hkdf`/`sha2` for `rustls` ECH.

use std::fmt;

use hkdf::Hkdf;
use ring::aead::{self, LessSafeKey, Nonce, UnboundKey};
use ring::agreement;
use ring::rand::{SecureRandom as _, SystemRandom};
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::{Error, OtherError};
use sha2::Sha256;

/// All ECH-compatible HPKE suites provided using `ring` primitives
/// (`DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305).
pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = &[
    &RingHpkeSuite {
        aead: HpkeAead::AES_128_GCM,
    },
    &RingHpkeSuite {
        aead: HpkeAead::AES_256_GCM,
    },
    &RingHpkeSuite {
        aead: HpkeAead::CHACHA20_POLY_1305,
    },
];

const N_SECRET: usize = 32;
const N_H: usize = 32;
const N_N: usize = 12;

#[derive(Debug)]
struct RingHpkeSuite {
    aead: HpkeAead,
}

impl RingHpkeSuite {
    fn suite_val(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: self.aead,
            },
        }
    }

    fn key_len(&self) -> Result<usize, Error> {
        match self.aead {
            HpkeAead::AES_128_GCM => Ok(16),
            HpkeAead::AES_256_GCM | HpkeAead::CHACHA20_POLY_1305 => Ok(32),
            _ => Err(hpke_err("unsupported HPKE AEAD")),
        }
    }

    fn aead_alg(&self) -> Result<&'static aead::Algorithm, Error> {
        match self.aead {
            HpkeAead::AES_128_GCM => Ok(&aead::AES_128_GCM),
            HpkeAead::AES_256_GCM => Ok(&aead::AES_256_GCM),
            HpkeAead::CHACHA20_POLY_1305 => Ok(&aead::CHACHA20_POLY1305),
            _ => Err(hpke_err("unsupported HPKE AEAD")),
        }
    }

    fn suite_id(&self) -> [u8; 10] {
        let aead_id = u16::from(self.aead).to_be_bytes();
        [
            b'H', b'P', b'K', b'E', 0x00, 0x20, // KEM = DHKEM_X25519_HKDF_SHA256
            0x00, 0x01, // KDF = HKDF-SHA256
            aead_id[0], aead_id[1],
        ]
    }

    fn key_schedule_base(
        &self,
        shared_secret: &[u8],
        info: &[u8],
    ) -> Result<(LessSafeKey, [u8; N_N]), Error> {
        let suite_id = self.suite_id();
        let psk_id_hash = labeled_extract(&suite_id, &[], b"psk_id_hash", &[]);
        let info_hash = labeled_extract(&suite_id, &[], b"info_hash", info);

        let mut context = Vec::with_capacity(1 + N_H + N_H);
        context.push(0x00); // mode_base
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);

        let secret = labeled_extract(&suite_id, shared_secret, b"secret", &[]);
        let nk = self.key_len()?;
        let key_bytes = labeled_expand(&suite_id, &secret, b"key", &context, nk)?;
        let nonce_bytes = labeled_expand(&suite_id, &secret, b"base_nonce", &context, N_N)?;

        let unbound = UnboundKey::new(self.aead_alg()?, &key_bytes)
            .map_err(|_| hpke_err("failed to build HPKE AEAD key"))?;
        let mut base_nonce = [0u8; N_N];
        base_nonce.copy_from_slice(&nonce_bytes);
        Ok((LessSafeKey::new(unbound), base_nonce))
    }
}

impl Hpke for RingHpkeSuite {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut sealer) = self.setup_sealer(info, pub_key)?;
        let ct = sealer.seal(aad, plaintext)?;
        Ok((enc, ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let rng = SystemRandom::new();
        let sk_e = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| hpke_err("X25519 ephemeral keygen failed"))?;
        let pk_e = sk_e
            .compute_public_key()
            .map_err(|_| hpke_err("X25519 public key computation failed"))?;
        let enc_bytes = pk_e.as_ref().to_vec();

        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, &pub_key.0);
        let shared = agreement::agree_ephemeral(sk_e, &peer, |dh| {
            extract_and_expand_x25519(dh, &enc_bytes, &pub_key.0)
        })
        .map_err(|_| hpke_err("X25519 agreement failed"))??;

        let (key, base_nonce) = self.key_schedule_base(&shared, info)?;
        Ok((
            EncapsulatedSecret(enc_bytes),
            Box::new(RingHpkeCtx {
                key,
                base_nonce,
                seq: 0,
            }),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let mut opener = self.setup_opener(enc, info, secret_key)?;
        opener.open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let sk_bytes: [u8; 32] = secret_key
            .secret_bytes()
            .try_into()
            .map_err(|_| hpke_err("X25519 secret key must be 32 bytes"))?;
        let enc_bytes: [u8; 32] = enc
            .0
            .as_slice()
            .try_into()
            .map_err(|_| hpke_err("X25519 encapsulated secret must be 32 bytes"))?;

        let pk_r = x25519_scalarmult_base(&sk_bytes);
        let dh = x25519_scalarmult(&sk_bytes, &enc_bytes);
        if dh.iter().all(|&b| b == 0) {
            return Err(hpke_err("X25519 decap produced zero shared secret"));
        }
        let shared = extract_and_expand_x25519(&dh, &enc_bytes, &pk_r)?;
        let (key, base_nonce) = self.key_schedule_base(&shared, info)?;
        Ok(Box::new(RingHpkeCtx {
            key,
            base_nonce,
            seq: 0,
        }))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let mut sk = [0u8; 32];
        SystemRandom::new()
            .fill(&mut sk)
            .map_err(|_| hpke_err("RNG failed"))?;
        let pk = x25519_scalarmult_base(&sk);
        Ok((
            HpkePublicKey(pk.to_vec()),
            HpkePrivateKey::from(sk.to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        self.suite_val()
    }
}

struct RingHpkeCtx {
    key: LessSafeKey,
    base_nonce: [u8; N_N],
    seq: u64,
}

impl fmt::Debug for RingHpkeCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingHpkeCtx").field("seq", &self.seq).finish()
    }
}

impl RingHpkeCtx {
    fn next_nonce(&mut self) -> Result<Nonce, Error> {
        if self.seq == u64::MAX {
            return Err(hpke_err("HPKE message limit reached"));
        }
        let seq_be = self.seq.to_be_bytes();
        let mut nonce = self.base_nonce;
        for (dst, &s) in nonce[N_N - 8..].iter_mut().zip(&seq_be) {
            *dst ^= s;
        }
        self.seq += 1;
        Ok(Nonce::assume_unique_for_key(nonce))
    }
}

impl HpkeSealer for RingHpkeCtx {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut buf)
            .map_err(|_| hpke_err("HPKE seal failed"))?;
        Ok(buf)
    }
}

impl HpkeOpener for RingHpkeCtx {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        let mut buf = ciphertext.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, aead::Aad::from(aad), &mut buf)
            .map_err(|_| Error::DecryptError)?;
        let len = plain.len();
        buf.truncate(len);
        Ok(buf)
    }
}

fn extract_and_expand_x25519(dh: &[u8], enc: &[u8], pk_r: &[u8]) -> Result<[u8; N_SECRET], Error> {
    if enc.len() != 32 || pk_r.len() != 32 {
        return Err(hpke_err("invalid X25519 key length"));
    }
    const KEM_SUITE_ID: [u8; 5] = [b'K', b'E', b'M', 0x00, 0x20];
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(enc);
    kem_context[32..].copy_from_slice(pk_r);

    let eae_prk = labeled_extract(&KEM_SUITE_ID, &[], b"eae_prk", dh);
    let expanded = labeled_expand(&KEM_SUITE_ID, &eae_prk, b"shared_secret", &kem_context, N_SECRET)?;
    let mut out = [0u8; N_SECRET];
    out.copy_from_slice(&expanded);
    Ok(out)
}

fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; N_H] {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);

    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut out = [0u8; N_H];
    out.copy_from_slice(&prk);
    out
}

fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; N_H],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    let l_u16 = u16::try_from(len).map_err(|_| hpke_err("HPKE expand length overflow"))?;
    let mut labeled_info = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&l_u16.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);

    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| hpke_err("invalid HKDF PRK"))?;
    let mut okm = vec![0u8; len];
    hk.expand(&labeled_info, &mut okm)
        .map_err(|_| hpke_err("HKDF expand failed"))?;
    Ok(okm)
}

fn hpke_err(msg: &str) -> Error {
    Error::Other(OtherError(std::sync::Arc::new(std::io::Error::other(
        msg.to_owned(),
    ))))
}

// ---------------------------------------------------------------------------
// Minimal RFC 7748 X25519 scalar multiplication (used for `open` & test vectors)
// ---------------------------------------------------------------------------

type Fe = [i64; 16];

fn fe_zero() -> Fe {
    [0; 16]
}

fn fe_one() -> Fe {
    let mut r = [0i64; 16];
    r[0] = 1;
    r
}

fn fe_unpack(input: &[u8; 32]) -> Fe {
    let mut out = [0i64; 16];
    for i in 0..16 {
        out[i] = i64::from(input[2 * i]) + (i64::from(input[2 * i + 1]) << 8);
    }
    out[15] &= 0x7fff;
    out
}

fn fe_pack(n: &Fe) -> [u8; 32] {
    let mut t = *n;
    fe_carry(&mut t);
    fe_carry(&mut t);
    fe_carry(&mut t);
    let mut m = [0i64; 16];
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fe_sel(&mut t, &mut m, 1 - b);
    }
    let mut out = [0u8; 32];
    for i in 0..16 {
        out[2 * i] = (t[i] & 0xff) as u8;
        out[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
    out
}

fn fe_carry(o: &mut Fe) {
    for i in 0..16 {
        o[i] += 1i64 << 16;
        let c = o[i] >> 16;
        let next = if i < 15 { c - 1 } else { 38 * (c - 1) };
        o[(i + 1) * usize::from(i < 15)] += next;
        o[i] -= c << 16;
    }
}

fn fe_sel(p: &mut Fe, q: &mut Fe, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = [0i64; 16];
    o.copy_from_slice(&t[..16]);
    fe_carry(&mut o);
    fe_carry(&mut o);
    o
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_inv(i: &Fe) -> Fe {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = fe_sq(&c);
        if a != 2 && a != 4 {
            c = fe_mul(&c, i);
        }
    }
    c
}

fn x25519_scalarmult(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut z = *scalar;
    z[0] &= 248;
    z[31] &= 127;
    z[31] |= 64;

    let x = fe_unpack(u);
    let mut a = fe_one();
    let mut b = x;
    let mut c = fe_zero();
    let mut d = fe_one();
    let mut a24 = fe_zero();
    a24[0] = 0xdb41;
    a24[1] = 1;

    for i in (0..=254).rev() {
        let r = i64::from((z[i >> 3] >> (i & 7)) & 1);
        fe_sel(&mut a, &mut b, r);
        fe_sel(&mut c, &mut d, r);
        let e = fe_add(&a, &c);
        a = fe_sub(&a, &c);
        c = fe_add(&b, &d);
        b = fe_sub(&b, &d);
        d = fe_sq(&e);
        let f = fe_sq(&a);
        a = fe_mul(&c, &a);
        c = fe_mul(&b, &e);
        let e = fe_add(&a, &c);
        a = fe_sub(&a, &c);
        b = fe_sq(&a);
        c = fe_sub(&d, &f);
        a = fe_mul(&c, &a24);
        a = fe_add(&a, &d);
        c = fe_mul(&c, &a);
        a = fe_mul(&d, &f);
        d = fe_mul(&b, &x);
        b = fe_sq(&e);
        fe_sel(&mut a, &mut b, r);
        fe_sel(&mut c, &mut d, r);
    }

    let c_inv = fe_inv(&c);
    let out = fe_mul(&a, &c_inv);
    fe_pack(&out)
}

fn x25519_scalarmult_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519_scalarmult(scalar, &base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7748_x25519_vector() {
        let scalar: [u8; 32] = hex::decode(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let u: [u8; 32] = hex::decode(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let expected =
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
        assert_eq!(hex::encode(x25519_scalarmult(&scalar, &u)), expected);
    }

    #[test]
    fn hpke_seal_and_open_roundtrip() {
        for suite in ALL_SUPPORTED_SUITES {
            let (pk, sk) = suite.generate_key_pair().unwrap();
            let info = b"tls ech";
            let aad = b"header";
            let pt = b"inner client hello";
            let (enc, ct) = suite.seal(info, aad, pt, &pk).unwrap();
            let got = suite.open(&enc, info, aad, &ct, &sk).unwrap();
            assert_eq!(got, pt);
        }
    }

    #[test]
    fn rfc9180_a1_key_schedule_and_decap_vector() {
        // RFC 9180 Appendix A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
        let sk_r = hex::decode("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
            .unwrap();
        let enc = hex::decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
            .unwrap();
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let aad = hex::decode("436f756e742d30").unwrap();
        let expected_pt =
            hex::decode("4265617574792069732074727574682c20747275746820626561757479").unwrap();
        let ct = hex::decode(
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
        )
        .unwrap();

        let suite = ALL_SUPPORTED_SUITES[0];
        let got = suite
            .open(
                &EncapsulatedSecret(enc),
                &info,
                &aad,
                &ct,
                &HpkePrivateKey::from(sk_r),
            )
            .unwrap();
        assert_eq!(got, expected_pt);
    }
}
