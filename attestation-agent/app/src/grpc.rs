// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::Parser;

use super::*;
use std::net::SocketAddr;

const DEFAULT_KEYPROVIDER_ADDR: &str = "127.0.0.1:50000";
const DEFAULT_GETRESOURCE_ADDR: &str = "127.0.0.1:50001";
const DEFAULT_ATTESTATION_AGENT_ADDR: &str = "127.0.0.1:50002";

lazy_static! {
    pub static ref ASYNC_ATTESTATION_AGENT: Arc<tokio::sync::Mutex<AttestationAgent>> =
        Arc::new(tokio::sync::Mutex::new(AttestationAgent::default()));
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// KeyProvider gRPC socket addr.
    ///
    /// This socket address which the KeyProvider gRPC service
    /// will listen to, for example:
    ///
    /// `--keyprovider_sock 127.0.0.1:11223`
    #[arg(default_value_t = DEFAULT_KEYPROVIDER_ADDR.to_string(), short, long = "keyprovider_sock")]
    keyprovider_sock: String,

    /// GetResource gRPC Unix socket addr.
    ///
    /// This socket address which the GetResource gRPC service
    /// will listen to, for example:
    ///
    /// `--getresource_sock 127.0.0.1:11223`
    #[arg(default_value_t = DEFAULT_GETRESOURCE_ADDR.to_string(), short, long = "getresource_sock")]
    getresource_sock: String,

    /// Attestation gRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation ttRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock 127.0.0.1:11223`
    #[arg(default_value_t = DEFAULT_ATTESTATION_AGENT_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,
}

pub async fn grpc_main() -> Result<()> {
    let cli = Cli::parse();

    let keyprovider_socket = cli.keyprovider_sock.parse::<SocketAddr>()?;

    let getresource_socket = cli.getresource_sock.parse::<SocketAddr>()?;

    let attestation_socket = cli.attestation_sock.parse::<SocketAddr>()?;

    debug!(
        "KeyProvider gRPC service listening on: {:?}",
        cli.keyprovider_sock
    );
    debug!(
        "GetResource gRPC service listening on: {:?}",
        cli.getresource_sock
    );
    debug!(
        "Attestation gRPC service listening on: {:?}",
        cli.attestation_sock
    );

    let keyprovider_server = rpc::keyprovider::grpc::start_grpc_service(keyprovider_socket);
    let getresource_server = rpc::getresource::grpc::start_grpc_service(getresource_socket);
    let attestation_server = rpc::attestation::grpc::start_grpc_service(attestation_socket);

    tokio::join!(keyprovider_server, getresource_server, attestation_server).0
}
