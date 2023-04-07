//! The `faucet` module provides an object for launching a Solana Faucet,
//! which is the custodian of any remaining lamports in a mint.
//! The Solana Faucet builds and sends airdrop transactions,
//! checking requests against a single-request cap and a per-IP limit
//! for a given time time_slice.

use {
    bincode::{deserialize, serialize},
    byteorder::{ByteOrder, LittleEndian},
    log::*,
    serde_derive::{Deserialize, Serialize},
    solana_sdk::{
        hash::Hash,
        instruction::Instruction,
        message::Message,
        native_token::lamports_to_sol,
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        system_instruction,
        transaction::Transaction,
    },
    std::{
        collections::{HashMap, HashSet},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    },
    thiserror::Error,
};

pub struct Faucet {
    faucet_keypair: Keypair,
    ip_cache: HashMap<IpAddr, u64>,
    address_cache: HashMap<Pubkey, u64>,
    pub time_slice: Duration,
    per_time_cap: Option<u64>,
    per_request_cap: Option<u64>,
    allowed_ips: HashSet<IpAddr>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum FaucetRequest {
    GetAirdrop {
        lamports: u64,
        to: Pubkey,
        blockhash: Hash,
    },
}

pub enum FaucetTransaction {
    Airdrop(Transaction),
    Memo((Transaction, String)),
}

pub const TIME_SLICE: u64 = 60;

pub trait LimitByTime {
    fn check_cache(&self, faucet: &mut Faucet, request_amount: u64) -> u64;
}

impl LimitByTime for IpAddr {
    fn check_cache(&self, faucet: &mut Faucet, request_amount: u64) -> u64 {
        *faucet
            .ip_cache
            .entry(*self)
            .and_modify(|total| *total = total.saturating_add(request_amount))
            .or_insert(request_amount)
    }
}

#[derive(Error, Debug)]
pub enum FaucetError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialize(#[from] bincode::Error),

    #[error("request too large; req: ◎{0}, cap: ◎{1}")]
    PerRequestCapExceeded(f64, f64),

    #[error("limit reached; req: ◎{0}, to: {1}, current: ◎{2}, cap: ◎{3}")]
    PerTimeCapExceeded(f64, String, f64, f64),
}

impl Faucet {
    pub fn new(
        faucet_keypair: Keypair,
        time_input: Option<u64>,
        per_time_cap: Option<u64>,
        per_request_cap: Option<u64>,
    ) -> Self {
        Self::new_with_allowed_ips(
            faucet_keypair,
            time_input,
            per_time_cap,
            per_request_cap,
            HashSet::new(),
        )
    }

    pub fn new_with_allowed_ips(
        faucet_keypair: Keypair,
        time_input: Option<u64>,
        per_time_cap: Option<u64>,
        per_request_cap: Option<u64>,
        allowed_ips: HashSet<IpAddr>,
    ) -> Self {
        let time_slice = Duration::new(time_input.unwrap_or(TIME_SLICE), 0);

        Self {
            faucet_keypair,
            ip_cache: HashMap::new(),
            address_cache: HashMap::new(),
            time_slice,
            per_time_cap,
            per_request_cap,
            allowed_ips,
        }
    }

    pub fn check_time_request_limit<T: LimitByTime + std::fmt::Display>(
        &mut self,
        request_amount: u64,
        to: T,
    ) -> Result<(), FaucetError> {
        let new_total = to.check_cache(self, request_amount);

        if let Some(cap) = self.per_time_cap {
            if new_total > cap {
                return Err(FaucetError::PerTimeCapExceeded(
                    lamports_to_sol(request_amount),
                    to.to_string(),
                    lamports_to_sol(new_total),
                    lamports_to_sol(cap),
                ));
            }
        }
        Ok(())
    }

    /// Checks per-request and per-time-ip limits; if both pass, this method returns a signed
    /// SystemProgram::Transfer transaction from the faucet keypair to the requested recipient. If
    /// the request exceeds this per-request limit, this method returns a signed SPL Memo
    /// transaction with the memo: `"request too large; req: <REQUEST> SOL cap: <CAP> SOL"`
    pub fn build_airdrop_transaction(
        &mut self,
        req: FaucetRequest,
        ip: IpAddr,
    ) -> Result<FaucetTransaction, FaucetError> {
        trace!("build_airdrop_transaction: {:?}", req);
        match req {
            FaucetRequest::GetAirdrop {
                lamports,
                to,
                blockhash,
            } => {
                let mint_pubkey = self.faucet_keypair.pubkey();
                info!(
                    "Requesting airdrop of {} SOL to {:?}",
                    lamports_to_sol(lamports),
                    to
                );

                if let Some(cap) = self.per_request_cap {
                    if lamports > cap {
                        let memo = format!(
                            "{}",
                            FaucetError::PerRequestCapExceeded(
                                lamports_to_sol(lamports),
                                lamports_to_sol(cap),
                            )
                        );
                        let memo_instruction = Instruction {
                            program_id: Pubkey::from(spl_memo::id().to_bytes()),
                            accounts: vec![],
                            data: memo.as_bytes().to_vec(),
                        };
                        let message = Message::new(&[memo_instruction], Some(&mint_pubkey));
                        return Ok(FaucetTransaction::Memo((
                            Transaction::new(&[&self.faucet_keypair], message, blockhash),
                            memo,
                        )));
                    }
                }
                if !ip.is_loopback() && !self.allowed_ips.contains(&ip) {
                    self.check_time_request_limit(lamports, ip)?;
                }

                let transfer_instruction =
                    system_instruction::transfer(&mint_pubkey, &to, lamports);
                let message = Message::new(&[transfer_instruction], Some(&mint_pubkey));
                Ok(FaucetTransaction::Airdrop(Transaction::new(
                    &[&self.faucet_keypair],
                    message,
                    blockhash,
                )))
            }
        }
    }

    /// Deserializes a received airdrop request, and returns a serialized transaction
    pub fn process_faucet_request(
        &mut self,
        bytes: &[u8],
        ip: IpAddr,
    ) -> Result<Vec<u8>, FaucetError> {
        let req: FaucetRequest = deserialize(bytes)?;

        info!("Airdrop transaction requested...{:?}", req);
        let res = self.build_airdrop_transaction(req, ip);
        match res {
            Ok(tx) => {
                let tx = match tx {
                    FaucetTransaction::Airdrop(tx) => {
                        info!("Airdrop transaction granted");
                        tx
                    }
                    FaucetTransaction::Memo((tx, memo)) => {
                        warn!("Memo transaction returned: {}", memo);
                        tx
                    }
                };
                let response_vec = bincode::serialize(&tx)?;

                let mut response_vec_with_length = vec![0; 2];
                LittleEndian::write_u16(&mut response_vec_with_length, response_vec.len() as u16);
                response_vec_with_length.extend_from_slice(&response_vec);

                Ok(response_vec_with_length)
            }
            Err(err) => {
                warn!("Airdrop transaction failed: {}", err);
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    #[macro_export]
    macro_rules! socketaddr {
        ($ip:expr, $port:expr) => {
            SocketAddr::from((Ipv4Addr::from($ip), $port))
        };
        ($str:expr) => {{
            let a: SocketAddr = $str.parse().unwrap();
            a
        }};
    }

    use {super::*, solana_sdk::system_instruction::SystemInstruction, std::time::Duration};

    #[test]
    fn test_check_time_request_limit() {
        let keypair = Keypair::new();
        let mut faucet = Faucet::new(keypair, None, Some(2), None);
        let ip = socketaddr!([203, 0, 113, 1], 1234).ip();
        assert!(faucet.check_time_request_limit(1, ip).is_ok());
        assert!(faucet.check_time_request_limit(1, ip).is_ok());
        assert!(faucet.check_time_request_limit(1, ip).is_err());
    }

    #[test]
    fn test_faucet_default_init() {
        let keypair = Keypair::new();
        let time_slice: Option<u64> = None;
        let per_time_cap: Option<u64> = Some(200);
        let per_request_cap: Option<u64> = Some(100);
        let faucet = Faucet::new(keypair, time_slice, per_time_cap, per_request_cap);
        assert_eq!(faucet.time_slice, Duration::new(TIME_SLICE, 0));
        assert_eq!(faucet.per_time_cap, per_time_cap);
        assert_eq!(faucet.per_request_cap, per_request_cap);
    }

    #[test]
    fn test_faucet_build_airdrop_transaction() {
        let to = Pubkey::new_unique();
        let blockhash = Hash::default();
        let request = FaucetRequest::GetAirdrop {
            lamports: 2,
            to,
            blockhash,
        };
        let ip = socketaddr!([203, 0, 113, 1], 1234).ip();

        let mint = Keypair::new();
        let mint_pubkey = mint.pubkey();
        let mut faucet = Faucet::new(mint, None, None, None);

        if let FaucetTransaction::Airdrop(tx) =
            faucet.build_airdrop_transaction(request, ip).unwrap()
        {
            let message = tx.message();

            assert_eq!(tx.signatures.len(), 1);
            assert_eq!(
                message.account_keys,
                vec![mint_pubkey, to, Pubkey::default()]
            );
            assert_eq!(message.recent_blockhash, blockhash);

            assert_eq!(message.instructions.len(), 1);
            let instruction: SystemInstruction =
                deserialize(&message.instructions[0].data).unwrap();
            assert_eq!(instruction, SystemInstruction::Transfer { lamports: 2 });
        } else {
            panic!("airdrop should succeed");
        }

        // Test per-time request cap
        let mint = Keypair::new();
        faucet = Faucet::new(mint, None, Some(2), None);
        let _tx = faucet.build_airdrop_transaction(request, ip).unwrap(); // first request succeeds
        let tx = faucet.build_airdrop_transaction(request, ip);
        assert!(tx.is_err());

        // Test multiple requests from loopback with different addresses succeed
        let mint = Keypair::new();
        faucet = Faucet::new(mint, None, Some(2), None);
        let ip = socketaddr!(Ipv4Addr::LOCALHOST, 0).ip();
        let other = Pubkey::new_unique();
        let _tx0 = faucet.build_airdrop_transaction(request, ip).unwrap(); // first request succeeds
        let request1 = FaucetRequest::GetAirdrop {
            lamports: 2,
            to: other,
            blockhash,
        };
        let _tx1 = faucet.build_airdrop_transaction(request1, ip).unwrap(); // first request succeeds
        let tx0 = faucet.build_airdrop_transaction(request, ip);
        assert!(!tx0.is_err());

        // Test multiple requests from allowed ip with different addresses succeed
        let mint = Keypair::new();
        let ip = socketaddr!([203, 0, 113, 1], 0).ip();
        let mut allowed_ips = HashSet::new();
        allowed_ips.insert(ip);
        faucet = Faucet::new_with_allowed_ips(mint, None, Some(2), None, allowed_ips);
        let _tx0 = faucet.build_airdrop_transaction(request, ip).unwrap(); // first request succeeds

        // Test per-request cap
        let mint = Keypair::new();
        let mint_pubkey = mint.pubkey();
        let mut faucet = Faucet::new(mint, None, None, Some(1));

        if let FaucetTransaction::Memo((tx, memo)) =
            faucet.build_airdrop_transaction(request, ip).unwrap()
        {
            let message = tx.message();

            assert_eq!(tx.signatures.len(), 1);
            assert_eq!(
                message.account_keys,
                vec![mint_pubkey, Pubkey::from(spl_memo::id().to_bytes())]
            );
            assert_eq!(message.recent_blockhash, blockhash);

            assert_eq!(message.instructions.len(), 1);
            let parsed_memo = std::str::from_utf8(&message.instructions[0].data).unwrap();
            let expected_memo = "request too large; req: ◎0.000000002, cap: ◎0.000000001";
            assert_eq!(parsed_memo, expected_memo);
            assert_eq!(memo, expected_memo);
        } else {
            panic!("airdrop attempt should result in memo tx");
        }
    }

    #[test]
    fn test_process_faucet_request() {
        let to = solana_sdk::pubkey::new_rand();
        let blockhash = Hash::new(to.as_ref());
        let lamports = 50;
        let req = FaucetRequest::GetAirdrop {
            lamports,
            blockhash,
            to,
        };
        let ip = socketaddr!([203, 0, 113, 1], 1234).ip();
        let req = serialize(&req).unwrap();

        let keypair = Keypair::new();
        let expected_instruction = system_instruction::transfer(&keypair.pubkey(), &to, lamports);
        let message = Message::new(&[expected_instruction], Some(&keypair.pubkey()));
        let expected_tx = Transaction::new(&[&keypair], message, blockhash);
        let expected_bytes = serialize(&expected_tx).unwrap();
        let mut expected_vec_with_length = vec![0; 2];
        LittleEndian::write_u16(&mut expected_vec_with_length, expected_bytes.len() as u16);
        expected_vec_with_length.extend_from_slice(&expected_bytes);

        let mut faucet = Faucet::new(keypair, None, None, None);
        let response = faucet.process_faucet_request(&req, ip);
        let response_vec = response.unwrap().to_vec();
        assert_eq!(expected_vec_with_length, response_vec);

        let bad_bytes = "bad bytes".as_bytes();
        assert!(faucet.process_faucet_request(bad_bytes, ip).is_err());
    }
}
