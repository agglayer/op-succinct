use anyhow::Result;
use crate::Proposer;
use metrics::gauge;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::grpc;

/// ProposerAgglayer embeds and extends the original Proposer with custom behavior
pub struct ProposerAgglayer<'a, P, N>
where
    P: alloy_provider::Provider<N> + 'static,
    N: alloy_provider::Network,
{
    /// The inner proposer that implements most of the functionality
    inner: Arc<Mutex<Proposer<P, N>>>,
    /// Shared reference to the original proposer - deprecated, will be removed
    inner_ref: &'a Proposer<P, N>,
}

impl<'a, P, N> ProposerAgglayer<'a, P, N>
where
    P: alloy_provider::Provider<N> + 'static + Send + Sync,
    N: alloy_provider::Network + Send + Sync,
{
    /// Create a new ProposerAgglayer that wraps an existing Proposer
    pub fn new(proposer: &'a Proposer<P, N>) -> Self {
        // Create an Arc<Mutex<>> wrapped copy of the proposer
        let inner = Arc::new(Mutex::new(proposer.clone()));
        
        Self {
            inner,
            inner_ref: proposer,
        }
    }

    /// Run the proposer with the modified run_loop_iteration method and start gRPC server
    pub async fn run(&self, grpc_addr: &str) -> Result<()> {
        // Start the gRPC server in a separate task
        let proposer_clone = self.inner.clone();
        let grpc_addr = grpc_addr.to_string();
        tokio::spawn(async move {
            if let Err(e) = grpc::start_grpc_server(proposer_clone, &grpc_addr).await {
                tracing::error!("gRPC server error: {}", e);
            }
        });

        // Initialize the proposer
        self.inner_ref.initialize_proposer().await?;

        gauge!("succinct_error_count").set(0.0);

        // Loop interval in seconds
        loop {
            // Wrap the entire loop body in a match to handle errors
            match self.run_loop_iteration().await {
                Ok(_) => {
                    // Normal sleep between iterations
                    tokio::time::sleep(std::time::Duration::from_secs(
                        self.inner_ref.driver_config.loop_interval_seconds,
                    ))
                    .await;
                }
                Err(e) => {
                    // Log the error
                    tracing::error!("Error in proposer loop: {}", e);
                    // Update the error gauge
                    let error_gauge = metrics::gauge!("succinct_error_count");
                    error_gauge.increment(1.0);
                    // Pause for 10 seconds before restarting
                    tracing::info!("Pausing for 10 seconds before restarting the process");
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            }
        }
    }

    /// Modified run_loop_iteration that adds custom behavior
    async fn run_loop_iteration(&self) -> Result<()> {
        // Validate the requester config matches the contract.
        self.inner_ref.validate_contract_config().await?;

        // Log the proposer metrics.
        self.inner_ref.log_proposer_metrics().await?;

        // Add new range requests to the database.
        self.inner_ref.add_new_ranges().await?;

        // Get all proof statuses of all requests in the proving state.
        self.inner_ref.handle_proving_requests().await?;

        // Request all unrequested proofs from the prover network.
        self.inner_ref.request_queued_proofs().await?;

        Ok(())
    }
}
