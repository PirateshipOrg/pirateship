// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

mod ed25519;
#[cfg(feature = "sha256")]
mod sha256;
#[cfg(not(feature = "sha256"))]
mod sha512;
mod service;
pub mod merkle;

#[cfg(test)]
mod tests;

pub use ed25519::*;
#[cfg(feature = "sha256")]
pub use sha256::*;
#[cfg(not(feature = "sha256"))]
pub use sha512::*;

pub use service::*;

pub use merkle::*;
