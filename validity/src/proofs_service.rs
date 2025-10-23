use alloy_primitives::{hex::FromHex, FixedBytes};
use alloy_provider::Provider;
use bincode::Options;
use tonic::{Code, Request, Response, Status};
use tracing::{debug, info, warn};

use crate::{
    OPSuccinctRequest, RequestMode,
    ValidityGauge, Proposer
};
use op_succinct_grpc::proofs::{
    proofs_server::Proofs, AggProofRequest, AggProofResponse, GetMockProofRequest,
    GetMockProofResponse,
};
use op_succinct_host_utils::{host::OPSuccinctHost, metrics::MetricsGauge};
use std::{sync::Arc, time::Instant};

pub struct Service<P, H>
where
    P: Provider + 'static,
    H: OPSuccinctHost,
{
    proposer: Arc<Proposer<P, H>>,
}

impl<P, H> Service<P, H>
where
    P: Provider + 'static,
    H: OPSuccinctHost,
{
    pub fn new(
        proposer: Arc<Proposer<P, H>>,
    ) -> Self {
        Self { proposer }
    }

    // Limit the L1 block number to the safe head if it is greater than the requested end block
    async fn limit_l1_block_number(
        &self,
        requested_end_block: u64,
        l1_block_number: u64,
    ) -> Result<u64, Status> {
        let safe_head = self
            .proposer.proof_requester
            .fetcher
            .get_l2_safe_head_from_l1_block_number(l1_block_number - 20)
            .await
            .map_err(|e| Status::internal(format!("Failed to get safe head: {}", e)))?;

        if safe_head < requested_end_block {
            return Ok(safe_head);
        }

        Ok(requested_end_block)
    }
}

#[tonic::async_trait]
impl<P, H> Proofs for Service<P, H>
// Update trait implementation
where
    P: Provider + 'static,
    H: OPSuccinctHost,
{
    #[tracing::instrument(name = "proofs.request_agg_proof", skip(self, request))]
    async fn request_agg_proof(
        // Update method name
        &self,
        request: Request<AggProofRequest>, // Update request type
    ) -> Result<Response<AggProofResponse>, Status> {
        // Update response type
        info!("Received AggProofRequest: {:?}", request);

        let req = request.into_inner();

        let l1_limited_end_block = self
            .limit_l1_block_number(req.requested_end_block, req.l1_block_number)
            .await
            .map_err(|e| {
                ValidityGauge::WitnessgenErrorCount.increment(1.0);
                Status::internal(format!("Failed to limit L1 block number: {}", e))
            })?;

        // Check if the requested end block is less or equal than the requested start block
        if l1_limited_end_block <= req.last_proven_block {
            return Err(Status::new(
                Code::InvalidArgument,
                "Requested end block must be greater than the last proven block",
            ));
        }

        // Limit according to the existing span proofs range
        // Fetch consecutive range proofs from the database.
        let range_proofs = self
            .proposer.proof_requester
            .db_client
            .get_consecutive_complete_range_proofs(
                req.last_proven_block as i64,
                l1_limited_end_block as i64,
                &self.proposer.program_config.commitments,
                self.proposer.requester_config.l1_chain_id,
                self.proposer.requester_config.l2_chain_id,
            )
            .await.map_err(|_| {
                Status::new(
                    Code::NotFound,
                    "No range proofs found for the requested range",
                )
            })?;

        // Error in case there's no range proofs
        // Validate the aggregation proof request
        match self.proposer.proof_requester.validate_aggregation_request(&range_proofs, &req).await {
            Ok(true) => {
                debug!(
                    "Aggregation request validated successfully: start_block={}, end_block={}",
                    range_proofs.first().unwrap().start_block,
                    range_proofs.last().unwrap().end_block
                );
            }
            Ok(false) => {
                warn!(
                    "Aggregation request validation failed: last_proven_block={}, l1_limited_end_block={}",
                    req.last_proven_block, l1_limited_end_block
                );
                return Err(Status::new(
                    Code::InvalidArgument,
                    "Aggregation request validation failed",
                ));
            }
            Err(e) => {
                warn!("Error validating aggregation request: {:?}", e);
                return Err(Status::new(
                    Code::Internal,
                    format!("Failed to validate aggregation request: {}", e),
                ));
            }
        };

        // Set the requested_end_block to the last block from the range proofs
        let end_block = range_proofs.last().unwrap().end_block;

        // Prepare the request and query the proof requester
        let op_request = OPSuccinctRequest::new_agg_request(
            if self.proposer.requester_config.mock { RequestMode::Mock } else { RequestMode::Real },
            req.last_proven_block as i64,
            end_block,
            self.proposer.program_config.commitments.range_vkey_commitment,
            self.proposer.program_config.commitments.agg_vkey_hash,
            self.proposer.program_config.commitments.rollup_config_hash,
            self.proposer.requester_config.l1_chain_id,
            self.proposer.requester_config.l2_chain_id,
            req.l1_block_number as i64,
            FixedBytes::<32>::from_hex(req.l1_block_hash).map_err(|e| {
                Status::invalid_argument(format!("Invalid hex string for block hash: {}", e))
            })?,
            self.proposer.driver_config.signer.address()
        );

        info!(
            request_type = ?op_request.req_type,
            start_block = op_request.start_block,
            end_block = op_request.end_block,
            l1_block_number = ?op_request.checkpointed_l1_block_number,
            l1_block_hash = ?op_request.checkpointed_l1_block_hash,
            "Starting witness generation"
        );

        let witnessgen_duration = Instant::now();
        // Generate the stdin needed for the proof. If this fails, retry the request.
        let stdin = match self.proposer.proof_requester.generate_proof_stdin(&op_request).await {
            Ok(stdin) => stdin,
            Err(e) => {
                ValidityGauge::WitnessgenErrorCount.increment(1.0);
                return Err(Status::new(
                    Code::Internal,
                    format!("Failed to generate proof stdin: {}", e),
                ));
            }
        };
        let duration = witnessgen_duration.elapsed();

        info!(
            request_type = ?op_request.req_type,
            start_block = op_request.start_block,
            end_block = op_request.end_block,
            l1_block_number = ?op_request.checkpointed_l1_block_number,
            l1_block_hash = ?op_request.checkpointed_l1_block_hash,
            duration_s = duration.as_secs(),
            "Completed witness generation"
        );

        let reply: AggProofResponse;
        if self.proposer.proof_requester.mock {
            let proof =
                self.proposer.proof_requester.generate_mock_agg_proof(&op_request, stdin).await.map_err(
                    |e| Status::internal(format!("Failed to generate mock proof: {}", e)),
                )?;

            // If it's a compressed proof, we need to serialize the entire struct with bincode.
            let proof_bytes = bincode::DefaultOptions::new()
                .with_big_endian()
                .with_fixint_encoding()
                .serialize(&proof)
                .unwrap();

            let proved_op_request = OPSuccinctRequest {
                proof: proof_bytes.into(),
                status: crate::db::RequestStatus::Complete,
                ..op_request.clone()
            };

            // Create an aggregation proof request to cover the range with the checkpointed L1 block
            // hash.
            let last_id =
                self.proposer.proof_requester.db_client.insert_request(&proved_op_request).await.map_err(
                    |e| Status::internal(format!("Failed to save request to DB: {}", e)),
                )?;

            if last_id > 0 {
                // Convert the last ID to FixedBytes32
                let last_id =
                    FixedBytes::<32>::from_hex(format!("{:064x}", last_id)).map_err(|e| {
                        Status::internal(format!("Failed to convert ID to FixedBytes: {}", e))
                    })?;

                reply = AggProofResponse {
                    last_proven_block: req.last_proven_block,
                    end_block: end_block as u64,
                    proof_request_id: alloy_primitives::Bytes::from(last_id).into(),
                };
            } else {
                return Err(Status::internal("No AGG proof request inserted in the Database"));
            }
        } else {
            let proof_id = self
                .proposer.proof_requester
                .request_agg_proof(stdin)
                .await
                .map_err(|e| Status::internal(format!("Failed to request proof: {}", e)))?;

            reply = AggProofResponse {
                last_proven_block: req.last_proven_block,
                end_block: end_block as u64,
                proof_request_id: alloy_primitives::Bytes::from(proof_id).into(),
            };
        }

        Ok(Response::new(reply))
    }

    #[tracing::instrument(name = "proofs.get_mock_proof", skip(self, request))]
    async fn get_mock_proof(
        &self,
        request: Request<GetMockProofRequest>,
    ) -> Result<Response<GetMockProofResponse>, Status> {
        let req = request.into_inner();

        // Fetch the mock proof from the database
        let mock_proof = self
            .proposer.proof_requester
            .db_client
            .get_agg_proof_by_id(req.proof_id)
            .await
            .map_err(|e| Status::not_found(format!("Mock proof not found: {}", e)))?;

        // Return the mock proof in the response
        let response = GetMockProofResponse { proof: mock_proof.into() };

        Ok(Response::new(response))
    }
}
