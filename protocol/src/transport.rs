// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared tarpc framing and serialization.

pub type Framed<In, Out> = tarpc::serde_transport::Transport<
    tokio::net::UnixStream,
    In,
    Out,
    tarpc::tokio_serde::formats::Bincode<In, Out>,
>;

pub fn framed<In: serde::de::DeserializeOwned, Out: serde::Serialize>(
    socket: tokio::net::UnixStream,
) -> Framed<In, Out> {
    let codec = tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec::builder()
        .max_frame_length(8 * 1024 * 1024)
        .new_framed(socket);
    tarpc::serde_transport::new(codec, tarpc::tokio_serde::formats::Bincode::default())
}
