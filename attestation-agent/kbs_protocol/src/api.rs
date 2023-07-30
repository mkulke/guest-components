// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use async_trait::async_trait;
use resource_uri::ResourceUri;

use crate::{keypair::TeeKeyPair, token_provider::Token};

#[async_trait]
pub trait PassportClientCapabilities {
    async fn get_token(&mut self) -> Result<(Token, TeeKeyPair)>;
}

#[async_trait]
pub trait KbsClientCapabilities {
    async fn get_resource(&mut self, resource_uri: ResourceUri) -> Result<Vec<u8>>;
}
