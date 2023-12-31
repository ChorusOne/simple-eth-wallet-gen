use std::{fmt::Write, fs::File, io::Read, path::Path};

use bip39::{Language, Mnemonic, MnemonicType, Seed as Bip39Seed};
use libsecp256k1::{PublicKey, SecretKey};
use rand::distributions::{Alphanumeric, DistString};
use serde_derive::Serialize;
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_keccak::{Hasher, Keccak};

const ADDRESS_LENGTH: usize = 40;
const ADDRESS_BYTES: usize = ADDRESS_LENGTH / 2;
const KECCAK_OUTPUT_BYTES: usize = 32;
const ADDRESS_BYTE_INDEX: usize = KECCAK_OUTPUT_BYTES - ADDRESS_BYTES;

#[derive(Serialize)]
struct WalletOutput {
    keystore: serde_json::Value,
    password: String,
    secretkey: String,
    mnemonic: String,
    address: String,
}

fn create_new_seed() -> Mnemonic {
    let mut bytes = vec![0u8; MnemonicType::Words24.entropy_bits() / 8];

    getrandom::getrandom(&mut bytes).expect("Failed to generate seed using getrandom(2)");

    Mnemonic::from_entropy(bytes.as_slice(), Language::English)
        .expect("Failed to generate mnemonic")
}

fn to_hex_string(slice: &[u8], expected_string_size: usize) -> String {
    let mut result = String::with_capacity(expected_string_size);

    for &byte in slice {
        write!(&mut result, "{:02x}", byte).expect("Unable to format the public key.");
    }

    result
}

pub fn main() {
    let mnemonic = match std::env::args().nth(1) {
        Some(input) => Mnemonic::from_phrase(&input, Language::English).expect("Invalid mnemonic"),
        None => create_new_seed(),
    };

    let seed = Bip39Seed::new(&mnemonic, "");

    // Use Metamask derivation path
    let key = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/60'/0'/0").unwrap();

    let secret = key.secret();

    let password = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);

    let mut rng = rand::thread_rng();

    // eth_keystore library only works with filesystem,
    // but we want to avoid writing the keystore into filesystem,
    // so use temporary in-memory file here.

    // Even though keystore is encrypted, writing it to disk still worse
    // than not writing, so it was decided to use dev/shm instead of tmp/

    let shm_path = format!("/dev/shm/");
    let name = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);

    let dir = Path::new(shm_path.as_str());
    eth_keystore::encrypt_key(
        dir,
        &mut rng,
        secret,
        password.as_str(),
        Some(name.as_str()),
    )
    .unwrap();

    let mut keystore_file =
        File::open(dir.join(name)).expect("Can not open rendered hot wallet keystore");

    let mut keystore_contents = String::new();
    keystore_file
        .read_to_string(&mut keystore_contents)
        .expect("Can not read rendered hot wallet keystore");

    // Address encoding
    let mut res: [u8; 32] = [0; 32];
    let secret_key = SecretKey::parse_slice(&secret).unwrap();
    let public_key = PublicKey::from_secret_key(&secret_key);
    let public_key_array = public_key.serialize();
    let mut keccak = Keccak::v256();
    keccak.update(&public_key_array[1..]);
    keccak.finalize(&mut res);
    let address = to_hex_string(&res[ADDRESS_BYTE_INDEX..], 40); // get rid of the constant 0x04 byte

    let keystore_data: serde_json::Value = serde_json::from_str(&keystore_contents).unwrap();

    let wallet = WalletOutput {
        keystore: keystore_data,
        password,
        secretkey: to_hex_string(&secret_key.serialize(), 32),
        mnemonic: mnemonic.to_string(),
        address: format!("0x{address}"),
    };

    println!("{}", serde_json::to_string_pretty(&wallet).unwrap());
}
