use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

// Include the generated proto code
pub mod proofs {
    tonic::include_proto!("proofs");
}

use proofs::proofs_server::{Proofs, ProofsServer};
use proofs::{AggProofRequest, AggProofResponse};

use crate::Proposer;

pub struct ProofsService<P, N>
where
    P: alloy_provider::Provider<N> + 'static,
    N: alloy_provider::Network,
{
    proposer: Arc<Mutex<Proposer<P, N>>>,
}

#[tonic::async_trait]
impl<P, N> Proofs for ProofsService<P, N>
where
    P: alloy_provider::Provider<N> + 'static + Send + Sync,
    N: alloy_provider::Network + Send + Sync,
{
    async fn request_agg_proof(
        &self,
        request: Request<AggProofRequest>,
    ) -> Result<Response<AggProofResponse>, Status> {
        let req = request.into_inner();
        let start = req.start as u64;
        let end = req.end as u64;
        let l1_block_number = req.l1_block_number as u64;
        let l1_block_hash = req.l1_block_hash;

        // Generate a unique ID for this request
        let request_id = Uuid::new_v4().to_string();

        tracing::info!(
            "Received proof request: start={}, end={}, l1_block_number={}, request_id={}",
            start,
            end,
            l1_block_number,
            request_id
        );

        // Lock the proposer and attempt to add the range
        let mut proposer = self.proposer.lock().await;
        match proposer
            .add_specific_range(start, end, l1_block_number, l1_block_hash)
            .await
        {
            Ok(_) => {
                tracing::info!("Successfully queued proof request: {}", request_id);
                let response = AggProofResponse {
                    status: proofs::agg_proof_response::Status::Accepted as i32,
                    request_id,
                    message: "Request accepted".to_string(),
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                if e.to_string().contains("already exists") {
                    tracing::warn!("Proof request already exists: {}", e);
                    let response = AggProofResponse {
                        status: proofs::agg_proof_response::Status::AlreadyRequested as i32,
                        request_id,
                        message: format!("Request already exists: {}", e),
                    };
                    Ok(Response::new(response))
                } else {
                    tracing::error!("Error processing proof request: {}", e);
                    let response = AggProofResponse {
                        status: proofs::agg_proof_response::Status::Error as i32,
                        request_id,
                        message: format!("Error: {}", e),
                    };
                    Ok(Response::new(response))
                }
            }
        }
    }
}

pub async fn start_grpc_server<P, N>(
    proposer: Arc<Mutex<Proposer<P, N>>>,
    addr: &str,
) -> Result<()>
where
    P: alloy_provider::Provider<N> + 'static + Send + Sync,
    N: alloy_provider::Network + Send + Sync,
{
    let addr = addr.parse().context("Failed to parse gRPC server address")?;

    let proofs_service = ProofsService { proposer };

    tracing::info!("Starting gRPC server on {}", addr);
    
    Server::builder()
        .add_service(ProofsServer::new(proofs_service))
        .serve(addr)
        .await
        .context("Failed to start gRPC server")?;

    Ok(())
}
