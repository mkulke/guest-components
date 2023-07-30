// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "background_check")]
pub mod background_check;

#[cfg(feature = "passport")]
pub mod passport;

use kbs_types::Tee;

use crate::{keypair::TeeKeyPair, token_provider::Token};

/// This Client is used to connect to the remote KBS.
pub struct KbsClient<T> {
    /// TEE Type
    pub(crate) _tee: Option<Tee>,

    /// The asymmetric key pair inside the TEE
    pub(crate) tee_key: TeeKeyPair,

    pub(crate) provider: T,

    /// Http client
    pub(crate) http_client: reqwest::Client,

    /// KBS Host URL
    pub(crate) kbs_host_url: String,

    /// token
    pub(crate) token: Option<Token>,
}

pub const KBS_PROTOCOL_VERSION: &str = "0.1.0";

pub const KBS_GET_RESOURCE_MAX_ATTEMPT: u64 = 3;

pub const KBS_PREFIX: &str = "kbs/v0";
