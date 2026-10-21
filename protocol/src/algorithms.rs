// SPDX-License-Identifier: GPL-2.0-or-later
//! strongSwan encryption/integrity IDs (crypter.h and signer.h). The standard
//! values are IKE transform IDs; values >= 1024 are strongSwan private IDs.
//! Netlink and rustix expose kernel constants, not these IKE identifiers.

pub mod encryption {
    pub const DES: u16 = 2;
    pub const TRIPLE_DES: u16 = 3;
    pub const CAST: u16 = 6;
    pub const BLOWFISH: u16 = 7;
    pub const NULL: u16 = 11;
    pub const AES_CBC: u16 = 12;
    pub const AES_CTR: u16 = 13;
    pub const AES_CCM_ICV8: u16 = 14;
    pub const AES_CCM_ICV12: u16 = 15;
    pub const AES_CCM_ICV16: u16 = 16;
    pub const AES_GCM_ICV8: u16 = 18;
    pub const AES_GCM_ICV12: u16 = 19;
    pub const AES_GCM_ICV16: u16 = 20;
    pub const NULL_AUTH_AES_GMAC: u16 = 21;
    pub const CAMELLIA_CBC: u16 = 23;
    pub const CHACHA20_POLY1305: u16 = 28;
    pub const UNDEFINED: u16 = 1024;
    pub const SERPENT_CBC: u16 = 1026;
    pub const TWOFISH_CBC: u16 = 1027;
}

pub mod integrity {
    pub const HMAC_MD5_96: u16 = 1;
    pub const HMAC_SHA1_96: u16 = 2;
    pub const AES_XCBC_96: u16 = 5;
    pub const HMAC_MD5_128: u16 = 6;
    pub const HMAC_SHA1_160: u16 = 7;
    pub const AES_CMAC_96: u16 = 8;
    pub const HMAC_SHA2_256_128: u16 = 12;
    pub const HMAC_SHA2_384_192: u16 = 13;
    pub const HMAC_SHA2_512_256: u16 = 14;
    pub const UNDEFINED: u16 = 1024;
    pub const HMAC_SHA2_256_96: u16 = 1026;
    pub const HMAC_SHA2_256_256: u16 = 1027;
    pub const HMAC_SHA2_384_384: u16 = 1028;
    pub const HMAC_SHA2_512_512: u16 = 1029;
}
