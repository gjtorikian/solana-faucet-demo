use {solana_faucet::faucet::Faucet, solana_sdk::signer::keypair::Keypair};

fn main() {
    let keypair = Keypair::new();

    let time_slice: Option<u64> = None;
    let per_time_cap: Option<u64> = Some(200);
    let per_request_cap: Option<u64> = Some(100);
    let faucet = Faucet::new(keypair, time_slice, per_time_cap, per_request_cap);

    // while stream.read_exact(&mut request).await.is_ok() {
    //     trace!("{:?}", request);

    //     let response = {
    //         match stream.peer_addr() {
    //             Err(e) => {
    //                 info!("{:?}", e.into_inner());
    //                 ERROR_RESPONSE.to_vec()
    //             }
    //             Ok(peer_addr) => {
    //                 let ip = peer_addr.ip();
    //                 info!("Request IP: {:?}", ip);

    //                 match faucet.lock().unwrap().process_faucet_request(&request, ip) {
    //                     Ok(response_bytes) => {
    //                         trace!("Airdrop response_bytes: {:?}", response_bytes);
    //                         response_bytes
    //                     }
    //                     Err(e) => {
    //                         info!("Error in request: {}", e);
    //                         ERROR_RESPONSE.to_vec()
    //                     }
    //                 }
    //             }
    //         }
    //     };
    //     stream.write_all(&response).await?;
    // }

    // Ok(())
}
