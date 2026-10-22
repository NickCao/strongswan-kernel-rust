// SPDX-License-Identifier: GPL-2.0-or-later
//! strongSwan bitfields. Serde's binary representation retains unknown bits.
use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct AddressTypes: u32 {
        const REGULAR = 1 << 0;
        const DOWN = 1 << 1;
        const IGNORED = 1 << 2;
        const VIRTUAL = 1 << 3;
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct KernelFeatures: u32 {
        const ESP_V3_TFC = 1 << 0;
        const REQUIRE_EXCLUDE_ROUTE = 1 << 1;
        const REQUIRE_UDP_ENCAPSULATION = 1 << 2;
        const NO_POLICY_UPDATES = 1 << 3;
        const POLICY_SPI = 1 << 4;
        const SA_USE_TIME = 1 << 5;
        const ACQUIRE_SEQ = 1 << 6;
    }
}
