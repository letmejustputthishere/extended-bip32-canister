use ic_cdk::{
    api::management_canister::ecdsa::{EcdsaCurve,EcdsaKeyId,EcdsaPublicKeyArgument, EcdsaPublicKeyResponse},
    export::{
        candid::CandidType,
        serde::Serialize,
        Principal,
    },
    update,
};
use std::str::FromStr;

use ic_crypto_extended_bip32::{
    DerivationIndex, DerivationPath,
};

#[derive(CandidType, Serialize, Debug)]
struct PublicKeyReplyString {
    pub public_key_hex: String,
    pub chain_code_hex: String,
}

type CanisterId = Principal;

#[update]
async fn get_public_key_from_ic(
    canister_id: CanisterId,
    derivation_path: Vec<Vec<u8>>,
    ecdsa_key_id: EcdsaKeyId,
) -> Result<PublicKeyReplyString, String> {
    let request = EcdsaPublicKeyArgument {
        canister_id: Some(canister_id),
        derivation_path,
        key_id: ecdsa_key_id,
    };

    let (res,): (EcdsaPublicKeyResponse,) =
        ic_cdk::call(mgmt_canister_id(), "ecdsa_public_key", (request,))
            .await
            .map_err(|e| format!("ecdsa_public_key failed {}", e.1))?;

    Ok(PublicKeyReplyString {
        public_key_hex: hex::encode(&res.public_key),
        chain_code_hex: hex::encode(&res.chain_code),
    })
}

#[update]
fn compute_public_key_locally(
    canister_id: CanisterId,
    derivation_path: Vec<Vec<u8>>,
    ecdsa_key_id: EcdsaKeyId,
) -> Result<PublicKeyReplyString, String> {
    match ecdsa_key_id.curve {
        EcdsaCurve::Secp256k1 => (),
        _ => return Err(format!("Curve not supported for key derivation"))
    }
    let master_key= match ecdsa_key_id.name.as_str(){
        "test_key_1" => "02f9ac345f6be6db51e1c5612cddb59e72c3d0d493c994d12035cf13257e3b1fa7",
        "key_1" => "02121bc3a5c38f38ca76487c72007ebbfd34bc6c4cb80a671655aa94585bbd0a02",
        _ => return Err(format!("Master key not available for the given curve name"))
    };

    let res = derive_public_key_from_master_key(canister_id, derivation_path,master_key)?;

    Ok(PublicKeyReplyString {
        public_key_hex: hex::encode(&res.public_key),
        chain_code_hex: hex::encode(&res.chain_code),
    })
}

fn mgmt_canister_id() -> CanisterId {
    CanisterId::from_str(&"aaaaa-aa").unwrap()
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of ic-crypto-extended-bip32) 
// fails to compile. This is necessary because getrandom by default fails 
// to compile for the wasm32-unknown-unknown target (which is required for
// deploying a canister). This custom implementation always fails, which is
// sufficient here because no randomness is involved in the key derivation.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

fn derive_public_key_from_master_key(
    canister_id: CanisterId,
    derivation_path: Vec<Vec<u8>>,
    master_key: &str,
) -> Result<EcdsaPublicKeyResponse, String> {

    let master_key = hex::decode(master_key).expect("Master key could not be deserialized");
    let master_chain_code = [0u8; 32];
    

    let mut path = vec![];
    let derivation_index = DerivationIndex(canister_id.as_slice().to_vec());
    path.push(derivation_index);

    for index in derivation_path {
        path.push(DerivationIndex(index));
    }
    let derivation_path = DerivationPath::new(path);

    let res = derivation_path
        .key_derivation(
            &master_key,
            &master_chain_code,
        )
        .map_err(|err| format!("Internal Error: {:?}", err))?;

    Ok(EcdsaPublicKeyResponse {
        public_key: res.derived_public_key,
        chain_code: res.derived_chain_code,
    })
}

#[test]
fn check_ckbtc_key() {
    let ckbtc_minter_id = CanisterId::from_str("mqygn-kiaaa-aaaar-qaadq-cai").unwrap();
    let ckbtc_public_key = "0222047a81d4f8a067031c89273d241b79a5a007c04dfaf36d07963db0b99097eb";
    let ckbtc_chain_code = "821aebb643bd97d319d2fd0b2e483d4e7de2ea9039ff67568b693e6abc14a03b";
    
    let master_key_id = EcdsaKeyId{curve: EcdsaCurve::Secp256k1, name: "key_1".to_string()};
    let derived_key = compute_public_key_locally(ckbtc_minter_id, vec![], master_key_id);

    assert!(derived_key.is_ok(), "{}", derived_key.unwrap_err());
    let derived_key=derived_key.unwrap();

    assert_eq!(ckbtc_public_key, derived_key.public_key_hex);
    assert_eq!(ckbtc_chain_code, derived_key.chain_code_hex);
}