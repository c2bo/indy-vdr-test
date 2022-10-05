use indy_data_types::anoncreds::cred_def::{CredentialDefinition, CredentialDefinitionData, CredentialDefinitionV1, SignatureType};
use indy_data_types::SchemaId;
use indy_vdr::common::error::VdrResult;
use indy_vdr::ledger::RequestBuilder;
use indy_vdr::pool::PreparedRequest;
use indy_vdr::utils::did::DidValue;
use indy_vdr::ledger::identifiers::CredentialDefinitionId;

// Create unsigned NYM Transaction
pub fn generate_tx_cred_def(
    builder: &RequestBuilder,
    did: &DidValue,
) -> VdrResult<PreparedRequest> {
    // Create nym request from seed

    let cred_def = CredentialDefinitionV1 {
        id: CredentialDefinitionId("".to_string()),
        schema_id: SchemaId("".to_string()),
        signature_type: SignatureType::CL,
        tag: "".to_string(),
        value: CredentialDefinitionData { primary: Default::default(), revocation: None }
    };
    let tx = builder.build_cred_def_request(did, CredentialDefinition::CredentialDefinitionV1(cred_def));

    return match tx {
        Ok(tx) => Ok(tx),
        Err(err) => Err(err),
    };
}