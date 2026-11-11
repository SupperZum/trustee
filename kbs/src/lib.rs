// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! KBS API server

#[cfg(feature = "as")]
pub mod attestation;

/// KBS config
pub mod config;
pub use config::KbsConfig;
pub mod token;

pub mod api_server;
pub use api_server::ApiServer;

pub(crate) mod crypto;

pub mod error;
pub mod plugins;
pub use error::*;

pub mod admin;
pub mod http;
pub mod jwe;

#[cfg(feature = "launch-gcp-credentials")]
pub mod gcp_launch_credential;
#[cfg(feature = "launch-gcp-credentials")]
pub mod gcp_launch_http;
#[cfg(feature = "launch-gcp-credentials")]
pub mod gcp_launch_resource;
#[cfg(feature = "launch-gcp-credentials")]
pub mod gcp_launch_session;
#[cfg(feature = "launch-credentials")]
pub mod launch_credential;
#[cfg(feature = "launch-http")]
pub mod launch_http;
#[cfg(feature = "launch-policy-capture")]
pub mod launch_policy;
#[cfg(feature = "launch-http")]
pub mod launch_resource;
#[cfg(feature = "launch-session")]
pub mod launch_session;

pub mod prometheus;
