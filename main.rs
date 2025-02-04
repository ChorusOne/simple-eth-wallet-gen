use clap::{App, Arg};
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
    publickey: String,
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

fn print_ecdsa_key_json(wallet: &WalletOutput) {
    let ecdsa_key_json = serde_json::json!({
        "address": wallet.address.trim_start_matches("0x"),
        "crypto": {
            "cipher": wallet.keystore["crypto"]["cipher"],
            "cipherparams": {
                "iv": wallet.keystore["crypto"]["cipherparams"]["iv"]
            },
            "ciphertext": wallet.keystore["crypto"]["ciphertext"],
            "kdf": wallet.keystore["crypto"]["kdf"],
            "kdfparams": wallet.keystore["crypto"]["kdfparams"],
            "mac": wallet.keystore["crypto"]["mac"]
        },
        "id": wallet.keystore["id"],
        "version": wallet.keystore["version"]
    });

    println!("\necdsa.key.json:");
    println!("{}", serde_json::to_string_pretty(&ecdsa_key_json).unwrap());
}

pub enum DerivationAlgorithm {
    Bip44Default = 0,
    MetamaskLegacy = 1,
}

impl DerivationAlgorithm {
    pub fn from_input(input: Option<String>) -> Self {
        match input {
            Some(input) => {
                if input == "--bip44" {
                    DerivationAlgorithm::Bip44Default
                } else if input == "--legacy" {
                    DerivationAlgorithm::MetamaskLegacy
                } else {
                    panic!("Unknown derivation algorithm: {input}, support only bip44 or legacy")
                }
            }
            None => DerivationAlgorithm::Bip44Default,
        }
    }
}



pub fn main() {
    let matches = App::new("Simple ETH Wallet Generator")
        .version("1.0")
        .about("Generates Ethereum wallets")
        .arg(
            Arg::new("mnemonic")
                .help("Use the specified mnemonic phrase")
                .required(false)
                .index(1),
        )
        .arg(
            Arg::new("bip44")
                .long("bip44")
                .help("Use BIP44 derivation path m/44'/60'/0'/0/0 (default)")
                .required(false),
        )
        .arg(
            Arg::new("legacy")
                .long("legacy")
                .help("Use Metamask legacy derivation path m/44'/60'/0'/0'/0")
                .required(false),
        )
        .arg(
            Arg::new("bip44-path")
                .long("bip44-path")
                .value_name("BIP44_PATH")
                .help("Sets the BIP44 derivation path")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("legacy-path")
                .long("legacy-path")
                .value_name("LEGACY_PATH")
                .help("Sets the legacy derivation path")
                .required(false)
                .takes_value(true),
        )
        .get_matches();

    let mnemonic = matches.value_of("mnemonic").map_or_else(
        || create_new_seed(),
        |phrase| Mnemonic::from_phrase(phrase, Language::English).expect("Invalid mnemonic"),
    );

    let mut algorithm = DerivationAlgorithm::Bip44Default;
    if matches.is_present("bip44") || matches.is_present("bip44-path") {
        algorithm = DerivationAlgorithm::Bip44Default;
    } else if matches.is_present("legacy") || matches.is_present("legacy-path") {
        algorithm = DerivationAlgorithm::MetamaskLegacy;
    }

    let seed = Bip39Seed::new(&mnemonic, "");

    // https://github.com/MyCryptoHQ/MyCrypto/issues/2070
    let mut bip44_path = String::from("m/44'/60'/0'/0/0");
    let mut legacy_path = String::from("m/44'/60'/0'/0");

    if let Some(path) = matches.value_of("bip44-path") {
        bip44_path = path.to_string();
        println!("bip44_path: {}", bip44_path);
    }

    if let Some(path) = matches.value_of("legacy-path") {
        legacy_path = path.to_string();
        println!("legacy_path: {}", legacy_path);
    }

    let path = match algorithm {
        DerivationAlgorithm::Bip44Default => bip44_path.as_str(),
        DerivationAlgorithm::MetamaskLegacy => legacy_path.as_str(),
    };

    // Use Metamask derivation path
    let key = ExtendedPrivKey::derive(seed.as_bytes(), path).unwrap();

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
        publickey: to_hex_string(&public_key_array, 64),
        mnemonic: mnemonic.to_string(),
        address: format!("0x{address}"),
    };

    println!("wallet:");
    println!("{}", serde_json::to_string_pretty(&wallet).unwrap());
    print_ecdsa_key_json(&wallet);
}
