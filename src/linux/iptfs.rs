// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux 6.14 IP-TFS UAPI additions missing in netlink-packet-xfrm 0.5.
//! Keep the extension in the packet crate's generic NLA representation.
use crate::{model::TunnelMode, rpc_api::IptfsConfig};
use netlink_packet_core::DefaultNla;
use netlink_packet_xfrm::{self as packet, XfrmAttrs};

// include/uapi/linux/xfrm.h in Linux 6.14.
const XFRM_MODE_IPTFS: u8 = 5;
const XFRMA_IPTFS_DROP_TIME: u16 = 36;
const XFRMA_IPTFS_REORDER_WINDOW: u16 = 37;
const XFRMA_IPTFS_DONT_FRAG: u16 = 38;
const XFRMA_IPTFS_INIT_DELAY: u16 = 39;
const XFRMA_IPTFS_MAX_QSIZE: u16 = 40;
const XFRMA_IPTFS_PKT_SIZE: u16 = 41;

pub(super) fn mode(mode: TunnelMode) -> u8 {
    match mode {
        TunnelMode::Tunnel => packet::XFRM_MODE_TUNNEL,
        TunnelMode::Iptfs => XFRM_MODE_IPTFS,
    }
}

pub(super) fn observed_mode(mode: u8) -> Option<TunnelMode> {
    match mode {
        packet::XFRM_MODE_TUNNEL => Some(TunnelMode::Tunnel),
        XFRM_MODE_IPTFS => Some(TunnelMode::Iptfs),
        _ => None,
    }
}

pub(super) fn attributes(
    config: &IptfsConfig,
    inbound: bool,
    peer_requires_no_fragmentation: bool,
) -> Vec<XfrmAttrs> {
    let attr = |kind, bytes| XfrmAttrs::Other(DefaultNla::new(kind, bytes));
    if inbound {
        vec![
            attr(
                XFRMA_IPTFS_DROP_TIME,
                config.drop_time.to_ne_bytes().to_vec(),
            ),
            attr(
                XFRMA_IPTFS_REORDER_WINDOW,
                config.reorder_window.to_ne_bytes().to_vec(),
            ),
        ]
    } else {
        let mut attrs = vec![
            attr(
                XFRMA_IPTFS_INIT_DELAY,
                config.init_delay.to_ne_bytes().to_vec(),
            ),
            attr(
                XFRMA_IPTFS_MAX_QSIZE,
                config.max_queue_size.to_ne_bytes().to_vec(),
            ),
            attr(
                XFRMA_IPTFS_PKT_SIZE,
                config.packet_size.to_ne_bytes().to_vec(),
            ),
        ];
        if config.dont_fragment || peer_requires_no_fragmentation {
            attrs.push(attr(XFRMA_IPTFS_DONT_FRAG, Vec::new()));
        }
        attrs
    }
}
