// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use crypto::decrypt;

use kbs_protocol::{KbsProtocolWrapper, KbsRequest, KBS_PREFIX};

use super::AnnotationPacket;
use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use resource_uri::ResourceUri;
use std::convert::TryFrom;
use url::{Host, Url};
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct KbsUri {
    url: Url,
    host: Host,
}

impl KbsUri {
    fn host(&self) -> &Host {
        &self.host
    }

    fn as_str(&self) -> &str {
        self.url.as_str().trim_end_matches('/')
    }

    pub fn with_resource(&self, resource: &ResourceUri) -> Result<String> {
        let kbs_addr = if let Some(port) = self.url.port() {
            format!("{}:{port}", self.host)
        } else {
            self.host.to_string()
        };

        if !resource.kbs_addr.is_empty() && resource.kbs_addr != kbs_addr {
            bail!(
                "The resource KBS host {} differs from the KBS URL one {kbs_addr}",
                resource.kbs_addr
            );
        }

        let kbs_addr = &self.as_str();
        let repo = &resource.repository;
        let r#type = &resource.r#type;
        let tag = &resource.tag;
        Ok(format!(
            "{kbs_addr}{KBS_PREFIX}/resource/{repo}/{type}/{tag}"
        ))
    }
}

pub struct Kbc {
    kbs_uri: KbsUri,
    token: Option<String>,
    kbs_protocol_wrapper: KbsProtocolWrapper,
}

#[async_trait]
impl KbcInterface for Kbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("Check API of this KBC is unimplemented."))
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        let key_url = self.resource_to_kbs_uri(&annotation_packet.kid)?;

        let key_data = self.kbs_protocol_wrapper().http_get(key_url).await?;
        let key = Zeroizing::new(key_data);

        decrypt(
            key,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.wrapped_data)?,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.iv)?,
            &annotation_packet.wrap_type,
        )
    }

    #[allow(unused_assignments)]
    async fn get_resource(&mut self, desc: ResourceUri) -> Result<Vec<u8>> {
        let resource_url = self.resource_to_kbs_uri(&desc)?;
        let data = self.kbs_protocol_wrapper().http_get(resource_url).await?;

        Ok(data)
    }
}

impl TryFrom<&str> for KbsUri {
    type Error = Error;

    fn try_from(kbs_url: &str) -> Result<Self> {
        let url = Url::parse(&kbs_url).map_err(|e| anyhow!("Invalid URL {kbs_url}: {e}"))?;
        let Some(host) = url.host() else {
            bail!("{kbs_url} is missing a host");
        };
        let host = host.to_owned();

        let kbs_uri = KbsUri { url, host };
        Ok(kbs_uri)
    }
}

impl Kbc {
    pub fn new(kbs_uri: String) -> Result<Kbc> {
        // Check the KBS URI validity
        let kbs_uri = kbs_uri.as_str().try_into()?;

        Ok(Kbc {
            kbs_uri,
            token: None,
            kbs_protocol_wrapper: KbsProtocolWrapper::new(vec![]).unwrap(),
        })
    }

    fn kbs_uri(&self) -> &str {
        self.kbs_uri.as_str()
    }

    fn kbs_protocol_wrapper(&mut self) -> &mut KbsProtocolWrapper {
        &mut self.kbs_protocol_wrapper
    }

    /// Convert a [`ResourceUri`] to a KBS URL.
    pub fn resource_to_kbs_uri(&self, resource: &ResourceUri) -> Result<String> {
        self.kbs_uri.with_resource(resource)
    }
}

#[cfg(test)]
mod tests {
    // use super::ResourceUri;
    // use crate::cc_kbc::KbsUri;
    use super::*;

    const RESOURCE_URL_PORT: &str = "kbs://127.0.0.1:8081/alice/cosign-key/213";
    const RESOURCE_URL_NO_PORT: &str = "kbs://127.0.0.1/alice/cosign-key/213";
    const RESOURCE_NO_HOST_URL: &str = "kbs:///alice/cosign-key/213";

    const KBS_URL_PORT: &str = "https://127.0.0.1:8081";
    const KBS_URL_NO_HOST: &str = "file:///tmp/wrong";
    const KBS_URL_NO_PORT: &str = "https://127.0.0.1";
    const KBS_INVALID_URL: &str = "kbs:///alice/cosign-key/213";

    const RESOURCE_KBS_URL_PORT: &str =
        "https://127.0.0.1:8081/kbs/v0/resource/alice/cosign-key/213";
    const RESOURCE_KBS_URL_NO_PORT: &str = "https://127.0.0.1/kbs/v0/resource/alice/cosign-key/213";

    #[test]
    fn invalid_uri() {
        let kbs_uri: Result<KbsUri> = KBS_INVALID_URL.try_into();
        assert!(kbs_uri.is_err());
    }

    #[test]
    fn no_host() {
        let kbs_uri: Result<KbsUri> = KBS_URL_NO_HOST.try_into();
        assert!(kbs_uri.is_err());
    }

    #[test]
    fn valid_uri() {
        let kbs_uri: Result<KbsUri> = KBS_URL_PORT.try_into();
        assert!(kbs_uri.is_ok());
    }

    fn to_kbs_uri(kbs_url: &str, resource_url: &str, expected_kbs_url: &str) {
        let resource: ResourceUri =
            serde_json::from_str(&format!("\"{resource_url}\"")).expect("deserialize failed");

        let kbs_uri: KbsUri = kbs_url.try_into().unwrap();

        println!("{} {:?}", resource.kbs_addr, kbs_uri);
        let resource_kbs_url = kbs_uri.with_resource(&resource);

        assert!(resource_kbs_url.is_ok());
        assert_eq!(resource_kbs_url.unwrap(), expected_kbs_url);
    }

    #[test]
    fn resource_port_to_kbs_uri() {
        to_kbs_uri(KBS_URL_PORT, RESOURCE_URL_PORT, RESOURCE_KBS_URL_PORT);
    }

    #[test]
    fn resource_no_port_to_kbs_uri() {
        to_kbs_uri(
            KBS_URL_NO_PORT,
            RESOURCE_URL_NO_PORT,
            RESOURCE_KBS_URL_NO_PORT,
        );
    }

    #[test]
    fn resource_no_host_to_kbs_uri() {
        to_kbs_uri(KBS_URL_PORT, RESOURCE_NO_HOST_URL, RESOURCE_KBS_URL_PORT);
    }
}
