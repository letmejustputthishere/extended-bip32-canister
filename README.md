# Extended BIP32 derivation

This canister shows how to derive extended-BIP32 ECDSA public keys in the same way as the `ecdsa_public_key` API of the Internet Computer. The canister exposes two interfaces to derive ECDSA public keys for a `canister_id` and using a `derivation_path`:

```
  /// Forwards the request to the management canister of the IC and returns the derived key
  /// and chain-code to the caller. 
  get_public_key_from_ic : (principal, vec blob, ecdsa_key_id) -> (
    variant { Ok: record { public_key_hex: text; chain_code_hex: text }; Err: text },
  );

  /// Computes the derived public key and chain-code using the master ECDSA public key
  /// stored in the canister.
  compute_public_key_locally : (principal, vec blob, ecdsa_key_id) -> (
    variant { Ok: record { public_key_hex: text; chain_code_hex: text }; Err: text },
  );

```

The two interfaces above can be used to verify that the public keys computed by the canister are consistent with the ones computed by the IC. The local computation only supports the key ID available on mainnet, i.e. `key_1` and `test_key_1`. If any other key ID is used, the local computation would return an error. The public key retrieval from the IC supports any key ID available on the network where the canister is deployed, e.g. in a local development environment the key is `dfx_test_key`. Any other key ID is not supported and would result in an error. 


## Master Public Keys on Mainnet:
The internet computer has two master public keys available on mainnet, a production key and a test key: 

```
/// Production key
production_key_id = EcdsaKeyId{ curve: EcdsaCurve::Secp256k1, name: "key_1"}
production_public_key = "02121bc3a5c38f38ca76487c72007ebbfd34bc6c4cb80a671655aa94585bbd0a02"

/// Test Key
test_key_id = EcdsaKeyId{ curve: EcdsaCurve::Secp256k1, name: "test_key_1"}
test_public_key = "02f9ac345f6be6db51e1c5612cddb59e72c3d0d493c994d12035cf13257e3b1fa7"
```

The Note that the local computation of public keys would not succeed for a key_id that does not coincide with the above.


## Running the project locally

If you have dfx installed you can run the canister locally using the following commands.

```bash
# Starts the replica, running in the background
dfx start --background

# Deploys your canisters to the replica and generates your candid interface
dfx deploy
```

**Warning:** the ECDSA key embedded in the local replica may not be stable, therefore the results returned by `get_public_key_from_ic` may not be consistent after restarting the replica.


## Calling the canister API

The interfaces of the canister can be called using dfx as follows

```bash
# Calls canister <bip32_canister_id> to compute the master public key of canister <other_canister_id> using an empty derivation path.
dfx canister call --network ic <bip32_canister_id> compute_public_key_locally '(principal "<other_canister_id>", blob "", record {name="key_1"; curve=variant {secp256k1}})'

# Calls canister <bip32_canister_id> to fetch the master public key of canister <other_canister_id> from the ic using an empty derivation path.
dfx canister call --network ic <bip32_canister_id> compute_public_key_locally '(principal "<other_canister_id>", blob "", record {name="key_1"; curve=variant {secp256k1}})'
```

When calling the canister running on the Internet Computer on Mainnet, the above calls should return the same key and chaincode for the same canister ID. By changing the empty `blob ""` it is possible to further derive keys for canisters.   


To call a canister deployed in the local development environment it is sufficient to remove `--network ic` from the above calls.