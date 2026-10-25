//! Kaspa-family bech32 addresses (CashAddr-style checksum, 8-char checksum, `prefix:payload`).
//! Hoosat uses the same scheme with `hoosat` / `hoosattest` prefixes.

use anyhow::{anyhow, bail, Result};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Address payload versions shared by Kaspa and Hoosat.
pub const VERSION_PUBKEY: u8 = 0; // 32-byte x-only Schnorr key
pub const VERSION_PUBKEY_ECDSA: u8 = 1; // 33-byte compressed ECDSA key
pub const VERSION_SCRIPT_HASH: u8 = 8; // 32-byte script hash

fn polymod(values: impl Iterator<Item = u8>) -> u64 {
    const GEN: [u64; 5] = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470];
    let mut c: u64 = 1;
    for d in values {
        let c0 = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ d as u64;
        for (i, g) in GEN.iter().enumerate() {
            if (c0 >> i) & 1 == 1 {
                c ^= g;
            }
        }
    }
    c ^ 1
}

fn conv8to5(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

fn conv5to8(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 5) | b as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
        bail!("invalid padding in address payload");
    }
    Ok(out)
}

fn checksum(prefix: &str, payload5: &[u8]) -> u64 {
    let it = prefix.bytes().map(|b| b & 0x1f).chain(std::iter::once(0)).chain(payload5.iter().copied()).chain([0u8; 8]);
    polymod(it)
}

/// Encodes `prefix:payload` where payload = version byte || key/hash bytes.
pub fn encode(prefix: &str, version: u8, data: &[u8]) -> String {
    let mut raw = Vec::with_capacity(data.len() + 1);
    raw.push(version);
    raw.extend_from_slice(data);
    let payload5 = conv8to5(&raw);
    let cs = checksum(prefix, &payload5);
    let mut cs5 = [0u8; 8];
    for (i, v) in cs5.iter_mut().enumerate() {
        *v = ((cs >> (5 * (7 - i))) & 31) as u8;
    }
    let body: String = payload5.iter().chain(cs5.iter()).map(|&v| CHARSET[v as usize] as char).collect();
    format!("{prefix}:{body}")
}

/// Decodes an address into (prefix, version, data), validating the checksum.
pub fn decode(addr: &str) -> Result<(String, u8, Vec<u8>)> {
    let (prefix, body) = addr.split_once(':').ok_or_else(|| anyhow!("address missing prefix"))?;
    if body.len() < 9 {
        bail!("address too short");
    }
    let values: Vec<u8> = body
        .bytes()
        .map(|c| {
            CHARSET.iter().position(|&x| x == c).map(|p| p as u8).ok_or_else(|| anyhow!("invalid char {}", c as char))
        })
        .collect::<Result<_>>()?;
    let (payload5, cs5) = values.split_at(values.len() - 8);
    let cs = cs5.iter().fold(0u64, |acc, &v| (acc << 5) | v as u64);
    if checksum(prefix, payload5) != cs {
        bail!("bad address checksum");
    }
    let raw = conv5to8(payload5)?;
    let (version, data) = raw.split_first().ok_or_else(|| anyhow!("empty payload"))?;
    Ok((prefix.to_string(), *version, data.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_kaspa_addresses_crate() {
        use kaspa_addresses::{Address, Prefix, Version};
        let key = [7u8; 32];
        let ours = encode("kaspatest", VERSION_PUBKEY, &key);
        let theirs: String = Address::new(Prefix::Testnet, Version::PubKey, &key).into();
        assert_eq!(ours, theirs);
        let ecdsa = [3u8; 33];
        let ours = encode("kaspa", VERSION_PUBKEY_ECDSA, &ecdsa);
        let theirs: String = Address::new(Prefix::Mainnet, Version::PubKeyECDSA, &ecdsa).into();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn decodes_hoosat_test_vectors() {
        // Vectors from HTND util/address_test.go
        for a in [
            "hoosat:qr35ennsep3hxfe7lnz5ee7j5jgmkjswsn35ennsep3hxfe7ln35cta93d2lg",
            "hoosattest:qputx94qseratdmjs0j395mq8u03er0x3l35ennsep3hxfe7ln35c67gazt36",
            "hoosat:qyp0r5mcq4rd5grj3652ra09u5dcgwqq9ntuswp247nama5quyj40eq0f28wqsx",
        ] {
            let (p, v, d) = decode(a).unwrap();
            assert_eq!(encode(&p, v, &d), a);
        }
    }
}
