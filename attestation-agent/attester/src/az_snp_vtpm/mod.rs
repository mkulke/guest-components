// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::Result;
use az_snp_vtpm::{imds, is_snp_cvm, vtpm};
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn detect_platform() -> bool {
    match is_snp_cvm() {
        Ok(is_snp) => is_snp,
        Err(err) => {
            debug!("Failed to retrieve Azure HCL data from vTPM: {}", err);
            false
        }
    }
}

const DEFAULT_RUNTIME_MEASUREMENT_PCR: u64 = 8;

#[derive(Debug, Default)]
pub struct AzSnpVtpmAttester;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: vtpm::Quote,
    report: Vec<u8>,
    vcek: String,
}

#[async_trait::async_trait]
impl Attester for AzSnpVtpmAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> anyhow::Result<String> {
        let report = vtpm::get_report()?;
        let quote = vtpm::get_quote(&report_data)?;
        let certs = imds::get_certs()?;
        let vcek = certs.vcek;

        let evidence = Evidence {
            quote,
            report,
            vcek,
        };

        Ok(serde_json::to_string(&evidence)?)
    }

    async fn extend_runtime_measurement(
        &self,
        events: Vec<Vec<u8>>,
        register_index: Option<u64>,
    ) -> Result<()> {
        let pcr = register_index.unwrap_or(DEFAULT_RUNTIME_MEASUREMENT_PCR) as u8;
        for event in events {
            let mut hasher = Sha256::new();
            hasher.update(event);
            let digest: [u8; 32] = hasher.finalize().into();
            vtpm::extend_pcr(pcr, &digest)?;
        }

        Ok(())
    }
}
