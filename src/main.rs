mod nym;
mod schema;
mod cred_def;

use clap::Parser;
use futures_executor::block_on;
use indy_vdr::common::error::VdrResult;
use indy_vdr::pool::helpers::perform_ledger_request;
use indy_vdr::pool::helpers::perform_refresh;
use indy_vdr::pool::{Pool, PoolBuilder, PoolTransactions, PreparedRequest, RequestResult, SharedPool};
use indy_vdr::utils::did;
use indy_vdr::utils::keys::PrivateKey;
use log::{debug, error, info};
use crate::cred_def::generate_tx_cred_def;
use crate::nym::{generate_tx_nym, long_did};
use crate::schema::generate_tx_schema;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Seed to sign transactions with
    #[clap(
        short = 's',
        long = "seed",
        default_value = "000000000000000000000000Trustee1"
    )]
    seed: String,

    /// Path to Pool transaction genesis file
    #[clap(
        short = 'g',
        long = "genesis",
        default_value = "./pool_transactions_genesis"
    )]
    genesis_file: String,

    /// Action to perform
    #[clap(short = 'a', long = "action", default_value = "get_flag")]
    action: String,
}

fn main() {
    let args: Args = Args::parse();

    env_logger::init();

    // Initialize pool
    let genesistxs = PoolTransactions::from_json_file(args.genesis_file.as_str()).unwrap();
    let pool_builder = PoolBuilder::default()
        .transactions(genesistxs.clone())
        .unwrap();
    let pool = pool_builder.into_shared().unwrap();
    let builder = pool.get_request_builder();

    info!("Refreshing pool");
    let (txns, _timing) = block_on(perform_refresh(&pool)).unwrap();

    let pool = if let Some(txns) = txns {
        let builder = {
            let mut pool_txns = genesistxs;
            pool_txns.extend_from_json(&txns).unwrap();
            PoolBuilder::default()
                .transactions(pool_txns.clone())
                .unwrap()
        };
        builder.into_shared().unwrap()
    } else {
        pool
    };

    let (did, private_key, _) =
        did::generate_did(Option::from(args.seed.as_bytes())).unwrap();
    let ldid = &long_did(&did);

    match args.action.to_ascii_lowercase().as_str() {
        "rev" => {
            info!("Creating rev_reg with problematic entries");

            let (mut tx_nym, _did, nym_priv_key, _ver_key) = generate_tx_nym(&builder, ldid).unwrap();
            sign_and_send(&pool, &mut tx_nym, &private_key).unwrap();

            let (mut tx_schema, _schema) = generate_tx_schema(&builder, ldid).unwrap();
            sign_and_send(&pool, &mut tx_schema, &nym_priv_key).unwrap();

            let mut tx_cred_def = generate_tx_cred_def(&builder, ldid).unwrap();
            sign_and_send(&pool, &mut tx_cred_def, &nym_priv_key).unwrap();
        }
        "flag" => {
            info!("Writing REV_STRATEGY_USE_COMPAT_ORDERING=False to ledger");
            let name = "REV_STRATEGY_USE_COMPAT_ORDERING";
            let value = "False".to_string();

            let mut req = builder
                .build_flag_request(
                    &ldid,
                    name.to_string(),
                    value,
                )
                .unwrap();
            sign_and_send(&pool, &mut req, &private_key).unwrap();
        }
        "get_flag" => {
            info!("Getting value for REV_STRATEGY_USE_COMPAT_ORDERING from ledger");
            let name = "REV_STRATEGY_USE_COMPAT_ORDERING";
            let req = builder
                .build_get_flag_request(None, name.to_string(), None, None)
                .unwrap();
            let (result, _timing) = block_on(perform_ledger_request(&pool, &req)).unwrap();
            match result {
                RequestResult::Reply(data) => {
                    info!("{}", data)
                }
                RequestResult::Failed(error) => {
                    error!("{}", error)
                }
            };
        }
        "get_nym" => {
            info!("Getting Steward NYM");
            let req = builder
                .build_get_nym_request(None, &ldid, None, None)
                .unwrap();
            let (result, _timing) = block_on(perform_ledger_request(&pool, &req)).unwrap();
            match result {
                RequestResult::Reply(data) => {
                    info!("{}", data)
                }
                RequestResult::Failed(error) => {
                    error!("{}", error)
                }
            };
        }
        _ => {}
    }
}

fn sign_and_send(pool: &SharedPool, req: &mut PreparedRequest, private_key: &PrivateKey) -> VdrResult<()> {
    // Create Signature
    req.set_signature(
        private_key
            .sign(req.get_signature_input().unwrap().as_bytes())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    // Send transaction to ledger
    let (res, _timing) = block_on(perform_ledger_request(pool, req))?;
    match res {
        RequestResult::Reply(data) => {
            debug!("Sent data to ledger: {}", data);
            Ok(())
        }
        RequestResult::Failed(error) => Err(error),
    }
}
