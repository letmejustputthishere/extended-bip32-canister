use candid::{CandidType, Principal};
use ic_cdk::{
    management_canister::{EcdsaKeyId, EcdsaPublicKeyArgs, EcdsaPublicKeyResult},
    update,
};
use serde::Serialize;
use std::{cell::RefCell, time::Duration};

use ic_crypto_extended_bip32::{DerivationIndex, DerivationPath};

#[derive(CandidType, Serialize, Debug, Clone)]
struct PublicKeyReplyString {
    pub public_key_hex: String,
    pub chain_code_hex: String,
}

type CanisterId = Principal;

thread_local! {
    static STATE : RefCell<Option<State>> = RefCell::default();
}

struct State {
    pub canister_id: CanisterId,
    pub ecdsa_key_id: EcdsaKeyId,
    pub canister_master_key: Option<PublicKeyReplyString>,
}

fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with_borrow(|s| f(s.as_ref().expect("BUG: state is not initialized")))
}

fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with_borrow_mut(|s| f(s.as_mut().expect("BUG: state is not initialized")))
}

fn initialize_state(state: State) {
    STATE.set(Some(state));
}

fn setup_timers() {
    ic_cdk_timers::set_timer(Duration::ZERO, || {
        ic_cdk::futures::spawn(async {
            let canister_id = read_state(|s| s.canister_id);
            let ecdsa_key_id = read_state(|s| s.ecdsa_key_id.clone());
            let canister_master_key =
                get_canister_key_from_ic(canister_id, ecdsa_key_id, Default::default())
                    .await
                    .expect("should derive canister key from ic");
            mutate_state(|s| s.canister_master_key = Some(canister_master_key));
        })
    });
}

#[ic_cdk::init]
fn init(canister_id: CanisterId, ecdsa_key_id: EcdsaKeyId) {
    initialize_state(State {
        canister_id,
        ecdsa_key_id,
        canister_master_key: None,
    });
    setup_timers();
}

#[ic_cdk::post_upgrade]
fn post_upgrade(canister_id: CanisterId, ecdsa_key_id: EcdsaKeyId) {
    initialize_state(State {
        canister_id,
        ecdsa_key_id,
        canister_master_key: None,
    });
    setup_timers();
}

#[update]
async fn get_canister_key_from_ic(
    canister_id: CanisterId,
    ecdsa_key_id: EcdsaKeyId,
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyReplyString, String> {
    let args = EcdsaPublicKeyArgs {
        canister_id: Some(canister_id),
        key_id: ecdsa_key_id,
        derivation_path,
    };

    let res: EcdsaPublicKeyResult = ic_cdk::management_canister::ecdsa_public_key(&args)
        .await
        .map_err(|err| format!("Internal Error: {:?}", err))?;

    Ok(PublicKeyReplyString {
        public_key_hex: hex::encode(&res.public_key),
        chain_code_hex: hex::encode(&res.chain_code),
    })
}

#[update]
fn compute_public_key_locally(
    derivation_path: Vec<Vec<u8>>,
) -> Result<PublicKeyReplyString, String> {
    let canister_master_key = read_state(|s| s.canister_master_key.clone())
        .expect("master key should be set during deployment");

    let res = derive_public_key_from_master_key(
        derivation_path,
        &canister_master_key.public_key_hex,
        &canister_master_key.chain_code_hex,
    )?;

    Ok(PublicKeyReplyString {
        public_key_hex: hex::encode(&res.public_key),
        chain_code_hex: hex::encode(&res.chain_code),
    })
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
    derivation_path: Vec<Vec<u8>>,
    canister_master_key: &str,
    canister_master_chain_code: &str,
) -> Result<EcdsaPublicKeyResult, String> {
    let master_key =
        hex::decode(canister_master_key).expect("Master key could not be deserialized");
    // let master_chain_code = [0u8; 32];
    let master_chain_code = hex::decode(canister_master_chain_code)
        .expect("Master Chain Code could not be deserialized");

    let mut path = vec![];

    for index in derivation_path {
        path.push(DerivationIndex(index));
    }
    let derivation_path = DerivationPath::new(path);

    let res = derivation_path
        .key_derivation(&master_key, &master_chain_code)
        .map_err(|err| format!("Internal Error: {:?}", err))?;

    Ok(EcdsaPublicKeyResult {
        public_key: res.derived_public_key,
        chain_code: res.derived_chain_code,
    })
}

#[test]
fn check_ckbtc_key() {
    // as returned from calling `ecdsa_public_key` with key_1, no derivation path and the ckbtc minter canister principal
    // the canister exposes `get_canister_key_from_ic` which is a proxy to the `ecdsa_public_key` call
    let ckbtc_master_public_key =
        "0222047a81d4f8a067031c89273d241b79a5a007c04dfaf36d07963db0b99097eb";
    let ckbtc_master_chain_code =
        "821aebb643bd97d319d2fd0b2e483d4e7de2ea9039ff67568b693e6abc14a03b";

    // as returned from calling `ecdsa_public_key` with key_1, derivation path 01 in hex and the ckbtc minter canister principal
    // the canister exposes `get_canister_key_from_ic` which is a proxy to the `ecdsa_public_key` call
    let public_key = "02f45b92cccc52dc86cd3a2671e27bd14fa8b9d660e68ab216037f81d4d58d2a84";
    let chain_code = "5430576376210b602392abd6306081e5966da1df134e558f3e3c52cc431c52e8";

    let derived_key = derive_public_key_from_master_key(
        vec![vec![1]],
        ckbtc_master_public_key,
        ckbtc_master_chain_code,
    );

    assert!(derived_key.is_ok(), "{}", derived_key.unwrap_err());
    let derived_key = derived_key.unwrap();

    assert_eq!(public_key, hex::encode(derived_key.public_key));
    assert_eq!(chain_code, hex::encode(derived_key.chain_code));
}
