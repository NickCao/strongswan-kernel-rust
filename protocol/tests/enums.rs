// SPDX-License-Identifier: GPL-2.0-or-later
use kernel_rust_protocol::*;
use rstest::rstest;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use tarpc::tokio_serde::{formats::Bincode, Deserializer, Serializer};

fn numeric_wire<T, N>(value: T, raw: N)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
    N: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let mut typed = std::pin::pin!(Bincode::<T, T>::default());
    let mut numbers = std::pin::pin!(Bincode::<N, N>::default());
    let encoded = typed.as_mut().serialize(&value).unwrap();
    assert_eq!(encoded, numbers.as_mut().serialize(&raw).unwrap());
    let frame = encoded.as_ref().into();
    assert_eq!(typed.as_mut().deserialize(&frame).unwrap(), value);
    assert_eq!(numbers.as_mut().deserialize(&frame).unwrap(), raw);
}

#[rstest]
#[case::modes(|raw| numeric_wire(IpsecMode::from(raw), raw), &[0, 1, 2, 3, 4, 5, 6, 7, u32::MAX])]
#[case::selectors(|raw| numeric_wire(SelectorKind::from(raw), raw), &[7, 8, 10, u32::MAX])]
#[case::directions(|raw| numeric_wire(PolicyDirection::from(raw), raw), &[0, 1, 2, 3, u32::MAX])]
#[case::policy_kinds(|raw| numeric_wire(PolicyKind::from(raw), raw), &[0, 1, 2, 3, u32::MAX])]
#[case::priority_classes(|raw| numeric_wire(PolicyPriority::from(raw), raw), &[0, 1, 2, 3, 4, u32::MAX])]
#[case::offload(|raw| numeric_wire(HwOffload::from(raw), raw), &[0, 1, 2, 3, 4, u32::MAX])]
#[case::dscp(|raw| numeric_wire(DscpCopy::from(raw), raw), &[0, 1, 2, 3, 4, u32::MAX])]
#[case::address_types(|raw| numeric_wire(AddressTypes::from_bits_retain(raw), raw), &[0, 1, 3, 5, 7, 15, 0x80000000, u32::MAX])]
#[case::kernel_features(|raw| numeric_wire(KernelFeatures::from_bits_retain(raw), raw), &[0, 1, 4, 16, 32, 64, 127, 0x80000000, u32::MAX])]
fn numeric_u32_fields(#[case] check: fn(u32), #[case] values: &[u32]) {
    for &value in values {
        check(value);
    }
}

#[rstest]
#[case::compression(|raw| numeric_wire(IpcompTransform::from(raw), raw), &[0, 1, 2, 3, 4, 5, u16::MAX])]
#[case::encryption(|raw| numeric_wire(EncryptionAlgorithm::from(raw), raw), &[0, 3, 12, 20, 28, 1024, u16::MAX])]
#[case::integrity(|raw| numeric_wire(IntegrityAlgorithm::from(raw), raw), &[0, 12, 13, 14, 1024, 1026, u16::MAX])]
fn numeric_u16_fields(#[case] check: fn(u16), #[case] values: &[u16]) {
    for &value in values {
        check(value);
    }
}
