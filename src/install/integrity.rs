use core::fmt;

use bun_base64::zig_base64::STANDARD_NO_PAD as base64;
use bun_core::strings;
use bun_sha_hmac::sha as Crypto;

// Digest lengths (bytes).
const SHA1_DIGEST_LEN: usize = 20;
const SHA256_DIGEST_LEN: usize = 32;
const SHA384_DIGEST_LEN: usize = 48;
const SHA512_DIGEST_LEN: usize = 64;

const DIGEST_BUF_LEN: usize = SHA512_DIGEST_LEN;
const EMPTY_DIGEST_BUF: [u8; DIGEST_BUF_LEN] = [0u8; DIGEST_BUF_LEN];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Integrity {
    pub tag: Tag,
    /// Possibly a Subresource Integrity value initially.
    /// We normalize it into raw digest bytes.
    pub value: [u8; DIGEST_BUF_LEN],
}

// SAFETY: `#[repr(C)]` with a `#[repr(transparent)] u8` tag + `[u8; 64]`.
// No padding bytes, fully initialized, `Copy + 'static`.
unsafe impl bytemuck::NoUninit for Integrity {}

impl Default for Integrity {
    fn default() -> Self {
        Self {
            tag: Tag::UNKNOWN,
            value: EMPTY_DIGEST_BUF,
        }
    }
}

impl Integrity {
    pub(crate) fn unknown() -> Self {
        Self::default()
    }

    pub(crate) fn is_known(&self) -> bool {
        self.tag.is_supported()
    }

    pub(crate) fn parse_sha_sum(buf: &[u8]) -> crate::Result<Integrity> {
        if buf.is_empty() {
            return Ok(Integrity::unknown());
        }

        let mut integrity = Integrity {
            tag: Tag::SHA1,
            ..Default::default()
        };

        let end = SHA1_DIGEST_LEN * 2;
        if buf.len() < end {
            return Err(crate::Error::InvalidCharacter);
        }
        if !end.is_multiple_of(2) {
            return Err(crate::Error::InvalidCharacter);
        }

        let mut out_i = 0;
        let mut i = 0;

        while i < end {
            integrity.value[out_i] = bun_core::fmt::hex_pair_value(buf[i], buf[i + 1])
                .ok_or(crate::Error::InvalidCharacter)?;
            out_i += 1;
            i += 2;
        }

        Ok(integrity)
    }

    pub(crate) fn parse(buf: &[u8]) -> Integrity {
        let mut strongest = Integrity::unknown();

        for entry in buf.split(|c: &u8| c.is_ascii_whitespace()) {
            let parsed = Self::parse_entry(entry);
            if parsed.tag.0 > strongest.tag.0 {
                strongest = parsed;
            }
        }

        strongest
    }

    fn parse_entry(buf: &[u8]) -> Integrity {
        if buf.len() < b"sha256-".len() {
            return Integrity::unknown();
        }

        let (tag, offset) = Tag::parse(buf);
        if !tag.is_supported() {
            return Integrity::unknown();
        }

        let expected_len = tag.digest_len();
        let input = Self::trim_integrity_suffix(&buf[offset..]);

        let Ok(decoded_size) = base64.decoder.calc_size_for_slice(input) else {
            return Integrity::unknown();
        };

        if decoded_size != expected_len {
            return Integrity::unknown();
        }

        let mut out = EMPTY_DIGEST_BUF;
        if base64
            .decoder
            .decode(&mut out[..expected_len], input)
            .is_err()
        {
            return Integrity::unknown();
        }

        Integrity { tag, value: out }
    }

    #[inline]
    fn trim_integrity_suffix(input: &[u8]) -> &[u8] {
        let mut s = input;

        if let Some(i) = strings::index_of_char(s, b'?') {
            s = &s[..i as usize];
        }

        let mut end = s.len();
        while end > 0 && s[end - 1] == b'=' {
            end -= 1;
        }

        &s[..end]
    }

    pub(crate) fn slice(&self) -> &[u8] {
        &self.value[..self.tag.digest_len()]
    }

    /// Compute a sha512 integrity hash from raw bytes (e.g. a downloaded tarball).
    pub(crate) fn for_bytes(bytes: &[u8]) -> Integrity {
        const LEN: usize = SHA512_DIGEST_LEN;

        let mut value = EMPTY_DIGEST_BUF;

        // SAFETY: engine is null (default).
        unsafe {
            Crypto::SHA512::hash(
                bytes,
                (&mut value[..LEN])
                    .try_into()
                    .expect("infallible: size matches"),
                core::ptr::null_mut(),
            )
        };

        Integrity {
            tag: Tag::SHA512,
            value,
        }
    }

    #[inline]
    pub fn verify(&self, bytes: &[u8]) -> bool {
        Self::verify_by_tag(self.tag, bytes, &self.value)
    }

    pub(crate) fn verify_by_tag(tag: Tag, bytes: &[u8], expected_digest: &[u8]) -> bool {
        let mut digest = EMPTY_DIGEST_BUF;

        match tag {
            Tag::SHA1 => {
                const LEN: usize = SHA1_DIGEST_LEN;
                let out: &mut [u8; LEN] = (&mut digest[..LEN])
                    .try_into()
                    .expect("infallible: size matches");
                // SAFETY: engine is null (default).
                unsafe { Crypto::SHA1::hash(bytes, out, core::ptr::null_mut()) };
                strings::eql_long(out, &expected_digest[..LEN], true)
            }
            Tag::SHA256 => {
                const LEN: usize = SHA256_DIGEST_LEN;
                let out: &mut [u8; LEN] = (&mut digest[..LEN])
                    .try_into()
                    .expect("infallible: size matches");
                // SAFETY: engine is null (default).
                unsafe { Crypto::SHA256::hash(bytes, out, core::ptr::null_mut()) };
                strings::eql_long(out, &expected_digest[..LEN], true)
            }
            Tag::SHA384 => {
                const LEN: usize = SHA384_DIGEST_LEN;
                let out: &mut [u8; LEN] = (&mut digest[..LEN])
                    .try_into()
                    .expect("infallible: size matches");
                // SAFETY: engine is null (default).
                unsafe { Crypto::SHA384::hash(bytes, out, core::ptr::null_mut()) };
                strings::eql_long(out, &expected_digest[..LEN], true)
            }
            Tag::SHA512 => {
                const LEN: usize = SHA512_DIGEST_LEN;
                let out: &mut [u8; LEN] = (&mut digest[..LEN])
                    .try_into()
                    .expect("infallible: size matches");
                // SAFETY: engine is null (default).
                unsafe { Crypto::SHA512::hash(bytes, out, core::ptr::null_mut()) };
                strings::eql_long(out, &expected_digest[..LEN], true)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.tag {
            Tag::SHA1 => "sha1-",
            Tag::SHA256 => "sha256-",
            Tag::SHA384 => "sha384-",
            Tag::SHA512 => "sha512-",
            _ => return Ok(()),
        };

        f.write_str(prefix)?;

        let mut base64_buf = [0u8; 512];
        let bytes = self.slice();

        // SAFETY: base64 alphabet is pure ASCII.
        f.write_str(unsafe {
            core::str::from_utf8_unchecked(base64.encoder.encode(&mut base64_buf, bytes))
        })?;

        // Consistent with yarn.lock.
        match self.tag {
            Tag::SHA1 => f.write_str("="),
            _ => f.write_str("=="),
        }
    }
}

// Any u8 must be a valid bit pattern, since this is read from on-disk lockfiles.
// A `#[repr(u8)] enum` would be UB for unknown discriminants, so use a transparent
// newtype with associated consts instead.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tag(pub u8);

// SAFETY: `#[repr(transparent)]` newtype over `u8`.
// Same layout as `u8`, no padding, `Copy + 'static`.
unsafe impl bytemuck::NoUninit for Tag {}

impl Tag {
    pub(crate) const UNKNOWN: Tag = Tag(0);
    /// "shasum" in the metadata.
    pub(crate) const SHA1: Tag = Tag(1);
    /// Subresource Integrity value.
    pub const SHA256: Tag = Tag(2);
    /// Subresource Integrity value.
    pub(crate) const SHA384: Tag = Tag(3);
    /// Subresource Integrity value.
    pub(crate) const SHA512: Tag = Tag(4);

    #[inline]
    pub fn is_supported(self) -> bool {
        self.0 >= Tag::SHA1.0 && self.0 <= Tag::SHA512.0
    }

    pub(crate) fn parse(buf: &[u8]) -> (Tag, usize) {
        let Some(i) = strings::index_of_char(&buf[0..buf.len().min(7)], b'-') else {
            return (Tag::UNKNOWN, 0);
        };

        let i = i as usize;
        if buf.len() <= i + 1 {
            return (Tag::UNKNOWN, 0);
        }

        match &buf[0..i] {
            b"sha1" => (Tag::SHA1, i + 1),
            b"sha256" => (Tag::SHA256, i + 1),
            b"sha384" => (Tag::SHA384, i + 1),
            b"sha512" => (Tag::SHA512, i + 1),
            _ => (Tag::UNKNOWN, 0),
        }
    }

    #[inline]
    pub(crate) fn digest_len(self) -> usize {
        match self {
            Tag::SHA1 => SHA1_DIGEST_LEN,
            Tag::SHA256 => SHA256_DIGEST_LEN,
            Tag::SHA384 => SHA384_DIGEST_LEN,
            Tag::SHA512 => SHA512_DIGEST_LEN,
            _ => 0,
        }
    }
}

/// Incremental hasher used by the streaming tarball extractor. Bytes are fed
/// as they arrive from the network so integrity can be verified without ever
/// holding the full tarball in memory.
///
/// When `expected.tag` is a supported algorithm we hash with that algorithm so
/// `verify()` can compare against the lockfile value. When there is no expected
/// value yet (first install of a GitHub/remote tarball) we may compute SHA-512
/// if `compute_if_missing` is true.
pub(crate) struct Streaming {
    pub expected: Integrity,
    pub hasher: Hasher,
}

pub(crate) enum Hasher {
    None,
    Sha1(Crypto::SHA1),
    Sha256(Crypto::SHA256),
    Sha384(Crypto::SHA384),
    Sha512(Crypto::SHA512),
}

impl Streaming {
    pub(crate) fn init(expected: &Integrity, compute_if_missing: bool) -> Streaming {
        Streaming {
            expected: *expected,
            hasher: match expected.tag {
                Tag::SHA1 => Hasher::Sha1(Crypto::SHA1::init()),
                Tag::SHA256 => Hasher::Sha256(Crypto::SHA256::init()),
                Tag::SHA384 => Hasher::Sha384(Crypto::SHA384::init()),
                Tag::SHA512 => Hasher::Sha512(Crypto::SHA512::init()),
                _ if compute_if_missing => Hasher::Sha512(Crypto::SHA512::init()),
                _ => Hasher::None,
            },
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        match &mut self.hasher {
            Hasher::None => {}
            Hasher::Sha1(h) => h.update(bytes),
            Hasher::Sha256(h) => h.update(bytes),
            Hasher::Sha384(h) => h.update(bytes),
            Hasher::Sha512(h) => h.update(bytes),
        }
    }

    pub(crate) fn finish(&mut self) -> Integrity {
        let mut out = EMPTY_DIGEST_BUF;

        match &mut self.hasher {
            Hasher::None => Integrity::unknown(),
            Hasher::Sha1(h) => {
                h.r#final(
                    (&mut out[..SHA1_DIGEST_LEN])
                        .try_into()
                        .expect("infallible: size matches"),
                );
                Integrity {
                    tag: Tag::SHA1,
                    value: out,
                }
            }
            Hasher::Sha256(h) => {
                h.r#final(
                    (&mut out[..SHA256_DIGEST_LEN])
                        .try_into()
                        .expect("infallible: size matches"),
                );
                Integrity {
                    tag: Tag::SHA256,
                    value: out,
                }
            }
            Hasher::Sha384(h) => {
                h.r#final(
                    (&mut out[..SHA384_DIGEST_LEN])
                        .try_into()
                        .expect("infallible: size matches"),
                );
                Integrity {
                    tag: Tag::SHA384,
                    value: out,
                }
            }
            Hasher::Sha512(h) => {
                h.r#final(
                    (&mut out[..SHA512_DIGEST_LEN])
                        .try_into()
                        .expect("infallible: size matches"),
                );
                Integrity {
                    tag: Tag::SHA512,
                    value: out,
                }
            }
        }
    }

    /// Returns true only when the computed digest matches `expected`.
    /// Unsupported or missing expected values do not pass.
    pub(crate) fn verify(&mut self) -> bool {
        if !self.expected.is_known() {
            return false;
        }

        let computed = self.finish();
        if computed.tag != self.expected.tag {
            return false;
        }

        let len = self.expected.tag.digest_len();
        strings::eql_long(
            &computed.value[..len],
            &self.expected.value[..len],
            true,
        )
    }
}

// Assert `Integrity::default().value` is all zero.
const _: () = {
    let buf = EMPTY_DIGEST_BUF;
    let mut i = 0;
    while i < DIGEST_BUF_LEN {
        assert!(buf[i] == 0, "Integrity buffer is not zeroed");
        i += 1;
    }
};
