use indy_credx::issuer::{create_revocation_registry, update_revocation_registry};
use indy_credx::tails::TailsFileWriter;
use indy_data_types::anoncreds::cred_def::CredentialDefinition;
use indy_data_types::anoncreds::rev_reg::{RevocationRegistry, RevocationRegistryDelta};
use indy_data_types::anoncreds::rev_reg_def::{
    IssuanceType, RegistryType, RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate, RevocationRegistryDefinitionV1,
};
use indy_vdr::common::error::VdrResult;
use indy_vdr::ledger::RequestBuilder;
use indy_vdr::pool::PreparedRequest;
use indy_vdr::utils::did::DidValue;
use std::collections::BTreeSet;
use indy_data_types::{RevocationRegistryId, CredentialDefinitionId};

pub fn generate_tx_rev_reg(
    builder: &RequestBuilder,
    did: &DidValue,
    cred_def: &CredentialDefinition,
    tag: &str,
) -> VdrResult<(
    PreparedRequest,
    RevocationRegistryDefinition,
    RevocationRegistryDefinitionPrivate,
    RevocationRegistry,
    RevocationRegistryDelta,
)> {
    // default to temp folder
    let mut writer = TailsFileWriter::new(None);
    let (rev_reg_def, rev_reg_def_private, rev_reg, reg_reg_delta) = create_revocation_registry(
        did,
        cred_def,
        tag,
        RegistryType::CL_ACCUM,
        IssuanceType::ISSUANCE_BY_DEFAULT,
        50,
        &mut writer,
    )
    .unwrap();
    // fix for old node version
    let mut raw_rev_reg_def: RevocationRegistryDefinitionV1 = match rev_reg_def {
        RevocationRegistryDefinition::RevocationRegistryDefinitionV1(c) => {
            c
        }
    };
    raw_rev_reg_def.cred_def_id = CredentialDefinitionId(raw_rev_reg_def.cred_def_id.strip_prefix("creddef:sov:did:sov:").unwrap().to_string());
    let rev_reg_def = RevocationRegistryDefinition::RevocationRegistryDefinitionV1(raw_rev_reg_def);
    let tx = builder.build_revoc_reg_def_request(did, rev_reg_def.clone());

    return match tx {
        Ok(tx) => Ok((tx, rev_reg_def, rev_reg_def_private, rev_reg, reg_reg_delta)),
        Err(err) => Err(err),
    };
}

pub fn generate_tx_init_rev_reg(
    builder: &RequestBuilder,
    did: &DidValue,
    rev_reg_def: &RevocationRegistryDefinition,
    rev_reg: &RevocationRegistry,
) -> VdrResult<PreparedRequest> {
    let tx = builder.build_revoc_reg_entry_request(
        did,
        rev_reg_def.id(),
        &RegistryType::CL_ACCUM,
        rev_reg.initial_delta(),
    );
    return match tx {
        Ok(tx) => Ok(tx),
        Err(err) => Err(err),
    };
}

pub fn generate_tx_update_rev_reg_entry(
    builder: &RequestBuilder,
    did: &DidValue,
    cred_def: &CredentialDefinition,
    rev_reg: &RevocationRegistry,
    rev_reg_priv: &RevocationRegistryDefinitionPrivate,
    rev_reg_def: &RevocationRegistryDefinition,
    revoked: impl Iterator<Item = i64>,
) -> VdrResult<(PreparedRequest, RevocationRegistry)> {
    let revoked_set = revoked.into_iter().fold(BTreeSet::new(), |mut tree, i| {
        tree.insert(i as u32);
        tree
    });
    let (rev_reg, rev_reg_delta) =
        update_revocation_registry(cred_def, rev_reg_def, rev_reg_priv, rev_reg, BTreeSet::new(), revoked_set)
            .unwrap();
    let tx = builder.build_revoc_reg_entry_request(
        did,
        rev_reg_def.id(),
        &RegistryType::CL_ACCUM,
        rev_reg_delta,
    );
    return match tx {
        Ok(tx) => Ok((tx, rev_reg)),
        Err(err) => Err(err),
    };
}

pub fn generate_tx_get_delta(
    builder: &RequestBuilder,
    rev_reg_def_id: &RevocationRegistryId,
) -> VdrResult<PreparedRequest> {
    let tx = builder.build_get_revoc_reg_delta_request(
        None,
        rev_reg_def_id,
        None,
        chrono::offset::Utc::now().timestamp(),
    );
    return match tx {
        Ok(tx) => Ok(tx),
        Err(err) => Err(err),
    };
}
