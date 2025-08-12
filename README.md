> [!IMPORTANT]
> Realted library: https://github.com/dfinity/ic-pub-key

# Extended BIP32 derivation

This is a fork of [andreacerulli/extended-bip32-canister](https://github.com/andreacerulli/extended-bip32-canister) with a key difference in the implementation approach. While the original repository implements BIP32 derivation using the IC's master public keys, this fork implements derivation using canister-specific master public keys. This approach allows for verification of derived keys against the actual keys used by specific canisters on the Internet Computer.

This canister is deployed on the Internet Computer mainnet with the canister ID `yobg6-hqaaa-aaaal-asdwq-cai`. You can interact with it directly on mainnet or deploy your own instance locally for development.

This canister shows how to derive extended-BIP32 ECDSA public keys in the same way as the `ecdsa_public_key` API of the Internet Computer, but locally. The canister exposes two interfaces to derive ECDSA public keys:

```
  /// Forwards the request to the management canister of the IC and returns the derived key
  /// and chain-code to the caller.
  get_canister_key_from_ic : (principal, ecdsa_key_id, vec blob) -> (
    variant { Ok: record { public_key_hex: text; chain_code_hex: text }; Err: text },
  );

  /// Computes the derived public key and chain-code locally using the canister master ECDSA public key
  /// stored in the canister.
  compute_public_key_locally : (vec blob) -> (
    variant { Ok: record { public_key_hex: text; chain_code_hex: text }; Err: text },
  );

```

The canister requires initialization with two arguments:

-   `canister_id`: The principal ID of the canister whose keys we want to derive
-   `ecdsa_key_id`: The ECDSA key configuration to use (e.g., `{name="key_1"; curve=variant {secp256k1}}`)

Upon initialization, the canister immediately fetches the canister's master public key from the IC and stores it internally. This stored key is then used for all subsequent calls to `compute_public_key_locally`. The `get_canister_key_from_ic` method, however, allows specifying different canister IDs and key configurations for each call.

## Obtaining Canister Master Keys

To obtain a canister's master public key and chain code, you can use the `get_canister_key_from_ic` method with an empty derivation path. For example, to get the ckBTC minter's master key:

```bash
# Get the ckBTC minter's master public key and chain code
dfx canister call --network ic yobg6-hqaaa-aaaal-asdwq-cai get_canister_key_from_ic '(
  principal "mqygn-kiaaa-aaaar-qaadq-cai",
  record {name="key_1"; curve=variant {secp256k1}},
  vec {}
)'
```

This will return both the master public key and chain code, which can be used to verify the correctness of key derivations. See the test in `src/lib.rs`.

## Example: ckBTC Minter Canister

For example, to work with the ckBTC minter canister on mainnet, you would initialize the canister with:

```bash
dfx deploy extended_bip32_derivation --ic --argument '(
  principal "mqygn-kiaaa-aaaar-qaadq-cai",
  record {
    name="key_1";
    curve=variant {secp256k1}
  }
)'
```

This will fetch the ckBTC minter's master public key from mainnet. You can then use this key to derive further keys by providing different derivation paths. For instance, to derive the key for the first derivation index:

```bash
# Get the derived key from the IC
dfx canister call --network ic extended_bip32_derivation get_canister_key_from_ic '(
  principal "mqygn-kiaaa-aaaar-qaadq-cai",
  record {
    name="key_1";
    curve=variant {secp256k1}
  },
  vec { blob "\01" }
)'

# Compute the same key locally using the stored master key
dfx canister call --network ic extended_bip32_derivation compute_public_key_locally '(
  vec { blob "\01" }
)'
```

Both calls should return the same key and chaincode, verifying that the local computation matches the IC's computation. This is what is being tested for at the end of `src/lib.rs`.

## Running the project locally

If you have dfx installed you can run the canister locally using the following commands.

```bash
# Starts the replica, running in the background
dfx start --background --clean

# Deploys your canisters to the replica and generates your candid interface
dfx deploy extended_bip32_derivation --argument '(
  principal "<target_canister_id>",
  record {
    name="dfx_test_key";
    curve=variant {secp256k1}
  }
)'
```

**Warning:** the ECDSA key embedded in the local replica may not be stable, therefore the results returned by `get_canister_key_from_ic` and `compute_public_key_locally` may not be consistent after restarting the replica.
