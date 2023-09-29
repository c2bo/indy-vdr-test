mod cred_def;
mod nym;
mod rev_reg;
mod schema;

use crate::cred_def::generate_tx_cred_def;
use crate::nym::{generate_tx_nym, long_did};
use crate::rev_reg::{
    generate_tx_get_delta, generate_tx_init_rev_reg, generate_tx_rev_reg,
    generate_tx_update_rev_reg_entry,
};
use crate::schema::generate_tx_schema;
use clap::Parser;
use futures_executor::block_on;
use indy_data_types::anoncreds::schema::Schema::SchemaV1;
use indy_vdr::common::error::VdrResult;
use indy_vdr::pool::helpers::perform_ledger_request;
use indy_vdr::pool::helpers::perform_refresh;
use indy_vdr::pool::{
    Pool, PoolBuilder, PoolTransactions, PreparedRequest, RequestResult, SharedPool,
};
use indy_vdr::utils::did;
use indy_vdr::utils::keys::PrivateKey;
use log::{error, info};
use serde_json::Value;

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
        default_value = "./pool_transactions_genesis",
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

    let (did, private_key, _) = did::generate_did(Option::from(args.seed.as_bytes()), None).unwrap();
    let ldid = &long_did(&did);

    match args.action.to_ascii_lowercase().as_str() {
        "rev" => {
            info!("Creating rev_reg with problematic entries");

            // Generate and send nym
            let (mut req_nym, did, nym_priv_key, _ver_key) =
                generate_tx_nym(&builder, ldid).unwrap();
            sign_and_send(&pool, &mut req_nym, Some(&private_key)).unwrap();
            info!("Nym {} created", did);

            // Generate and send schema
            let (mut req_schema, schema) = generate_tx_schema(&builder, &did).unwrap();
            let resp = sign_and_send(&pool, &mut req_schema, Some(&nym_priv_key)).unwrap();
            info!("Schema {} created", schema.id());

            // Add seq_no to schema
            let res: Value = serde_json::from_str(&resp).unwrap();
            let seq_no = res["result"]["txnMetadata"]["seqNo"].as_u64().unwrap();

            let schema = match schema {
                SchemaV1(s) => {
                    let mut schema = s.clone();
                    schema.seq_no = Some(seq_no as u32);
                    SchemaV1(schema)
                }
            };

            // Generate and send cred_def
            let (mut req_cred_def, cred_def, _cred_priv) =
                generate_tx_cred_def(&builder, &did, &schema, "testcred").unwrap();
            sign_and_send(&pool, &mut req_cred_def, Some(&nym_priv_key)).unwrap();
            info!("Cred_Def {} created", cred_def.id());

            // Generate and send revocation registry + definition
            let (mut req_rev_reg_def, rev_reg_def, rev_reg_priv, rev_reg, _rev_reg_delta) =
                generate_tx_rev_reg(&builder, &did, &cred_def, "1.0").unwrap();
            sign_and_send(&pool, &mut req_rev_reg_def, Some(&nym_priv_key)).unwrap();
            info!("rev_reg_def {} created", rev_reg_def.id());
            let mut req_rev_reg =
                generate_tx_init_rev_reg(&builder, &did, &rev_reg_def, &rev_reg).unwrap();
            sign_and_send(&pool, &mut req_rev_reg, Some(&nym_priv_key)).unwrap();
            info!("rev_reg created");

            // Create revocation entry
            let (mut req_rev_entry, rev_reg) = generate_tx_update_rev_reg_entry(
                &builder,
                &did,
                &cred_def,
                &rev_reg,
                &rev_reg_priv,
                &rev_reg_def,
                vec![1, 5, 6, 7].into_iter(),
            )
            .unwrap();
            sign_and_send(&pool, &mut req_rev_entry, Some(&nym_priv_key)).unwrap();
            info!("revoked indices [1, 5, 6, 7]");
            // Create revocation entry
            let (mut req_rev_entry, _rev_reg) = generate_tx_update_rev_reg_entry(
                &builder,
                &did,
                &cred_def,
                &rev_reg,
                &rev_reg_priv,
                &rev_reg_def,
                vec![8].into_iter(),
            )
            .unwrap();
            sign_and_send(&pool, &mut req_rev_entry, Some(&nym_priv_key)).unwrap();
            info!("revoked index [8]");

            // Get delta
            let mut req_delta = generate_tx_get_delta(&builder, rev_reg_def.id()).unwrap();
            let resp = sign_and_send(&pool, &mut req_delta, None).unwrap();
            let res: Value = serde_json::from_str(&resp).unwrap();
            // parse delta
            let revoked = res["result"]["data"]["value"]["revoked"].as_array().unwrap();
            info!("Got delta: {:?}", revoked);
        }
        "flag" => {
            info!("Writing REV_STRATEGY_USE_COMPAT_ORDERING=False to ledger");
            let name = "REV_STRATEGY_USE_COMPAT_ORDERING";
            let value = "False".to_string();

            let mut req = builder
                .build_flag_request(&ldid, name.to_string(), value)
                .unwrap();
            sign_and_send(&pool, &mut req, Some(&private_key)).unwrap();
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

// Helper function to sign and send transactions
fn sign_and_send(
    pool: &SharedPool,
    req: &mut PreparedRequest,
    private_key: Option<&PrivateKey>,
) -> VdrResult<String> {
    // Create Signature
    if private_key.is_some() {
        req.set_signature(
            private_key
                .unwrap()
                .sign(req.get_signature_input()?.as_bytes())?
                .as_slice(),
        )?;
    }
    // Send transaction to ledger
    let (res, _timing) = block_on(perform_ledger_request(pool, &req))?;
    match res {
        RequestResult::Reply(data) => Ok(data),
        RequestResult::Failed(error) => Err(error),
    }
}
