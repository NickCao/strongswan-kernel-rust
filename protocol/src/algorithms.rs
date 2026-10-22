// SPDX-License-Identifier: GPL-2.0-or-later
//! strongSwan encryption/integrity IDs (crypter.h and signer.h).
use num_enum::{FromPrimitive, IntoPrimitive};
use serde::{Deserialize, Serialize};

/// Encryption transform IDs, including strongSwan private values.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u16)]
#[serde(from = "u16", into = "u16")]
pub enum EncryptionAlgorithm {
    DesIv64 = 1,
    Des = 2,
    TripleDes = 3,
    Rc5 = 4,
    Idea = 5,
    Cast = 6,
    Blowfish = 7,
    TripleIdea = 8,
    DesIv32 = 9,
    Null = 11,
    AesCbc = 12,
    AesCtr = 13,
    AesCcmIcv8 = 14,
    AesCcmIcv12 = 15,
    AesCcmIcv16 = 16,
    AesGcmIcv8 = 18,
    AesGcmIcv12 = 19,
    AesGcmIcv16 = 20,
    NullAuthAesGmac = 21,
    CamelliaCbc = 23,
    CamelliaCtr = 24,
    CamelliaCcmIcv8 = 25,
    CamelliaCcmIcv12 = 26,
    CamelliaCcmIcv16 = 27,
    ChaCha20Poly1305 = 28,
    Undefined = 1024,
    DesEcb = 1025,
    SerpentCbc = 1026,
    TwofishCbc = 1027,
    Rc2Cbc = 1028,
    AesEcb = 1029,
    AesCfb = 1030,
    #[num_enum(catch_all)]
    Other(u16),
}

/// Integrity transform IDs, including strongSwan private values.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u16)]
#[serde(from = "u16", into = "u16")]
pub enum IntegrityAlgorithm {
    HmacMd5Icv96 = 1,
    HmacSha1Icv96 = 2,
    DesMac = 3,
    KpdkMd5 = 4,
    AesXcbcIcv96 = 5,
    HmacMd5Icv128 = 6,
    HmacSha1Icv160 = 7,
    AesCmacIcv96 = 8,
    Aes128Gmac = 9,
    Aes192Gmac = 10,
    Aes256Gmac = 11,
    HmacSha256Icv128 = 12,
    HmacSha384Icv192 = 13,
    HmacSha512Icv256 = 14,
    Undefined = 1024,
    HmacSha1Icv128 = 1025,
    HmacSha256Icv96 = 1026,
    HmacSha256Icv256 = 1027,
    HmacSha384Icv384 = 1028,
    HmacSha512Icv512 = 1029,
    CamelliaXcbcIcv96 = 1030,
    #[num_enum(catch_all)]
    Other(u16),
}
