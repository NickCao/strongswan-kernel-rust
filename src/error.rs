// SPDX-License-Identifier: GPL-2.0-or-later
pub fn invalid() -> std::io::Error {
    std::io::Error::from_raw_os_error(libc::EINVAL)
}
pub fn unsupported() -> std::io::Error {
    std::io::Error::from_raw_os_error(libc::EOPNOTSUPP)
}
