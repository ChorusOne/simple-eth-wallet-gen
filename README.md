simple-wallet-gen
=================

Generate Metamask-compatible Ethereum wallet into standard output, using only memory.

Installation
------------
1. Install Cargo as described at [Cargo website](https://doc.rust-lang.org/cargo/getting-started/installation.html)
2. Invoke `cargo build`


Generate new mnemonic
---------------------

```bash
./target/debug/simple-eth-wallet-gen
{
  "keystore": {
    "crypto": {
      "cipher": "aes-128-ctr",
      "cipherparams": {
        "iv": "3227127c7ec04743245e4e463cdcb3a9"
      },
      "ciphertext": "5d8320d7b980c05a31c7816002ab7a68e375cae7eb013a9636b2e94b5f0a2d10",
      "kdf": "scrypt",
      "kdfparams": {
        "dklen": 32,
        "n": 8192,
        "p": 1,
        "r": 8,
        "salt": "5075e5416944a41fa00c7f3402b16ed3be0ff4fc8dd1b97da2083b0a8ed17ef3"
      },
      "mac": "0d4824f9c06784ec359dcee9e6d40b7ef6bd36dcabc40ef5a848417a66605ba1"
    },
    "id": "c7231625-6b1f-42ab-ba0a-46fb868c2c85",
    "version": 3
  },
  "password": "CSM8zroHbwDsAOwKq2Dvn6J6GhyqWzeu",
  "secretkey": "f0bee2ddbfbe7792f31a77906a1e4b379be1fb6d5376f01645f173866d254767",
  "mnemonic": "syrup session ill fetch same river joy expose index voyage forget fog tent pumpkin hard domain neck happy cloud give canal priority sample fish",
  "address": "0x65ad46610b0d90686a79b36b5fd476f63b9997c6"
}
```

Import existing mnemonic
------------------------

```bash
./target/debug/simple-eth-wallet-gen "syrup session ill fetch same river joy expose index voyage forget fog tent pumpkin hard domain neck happy cloud give canal priority sample fish"
{
  "keystore": {
    "crypto": {
      "cipher": "aes-128-ctr",
      "cipherparams": {
        "iv": "f964144b9dae4b5e8b4c73caa314e448"
      },
      "ciphertext": "3e53665c056cc85c8a7469f033ae201f1a5da9aadac1d61537a5ba9baa5f5983",
      "kdf": "scrypt",
      "kdfparams": {
        "dklen": 32,
        "n": 8192,
        "p": 1,
        "r": 8,
        "salt": "d719d2c736d6db5d4f5320ef675c74906070402c97aa52c209eddfed178eca20"
      },
      "mac": "0f7f3530580d1eea8a6f2ca6559624b031b863585373c7d7700e1312427b45d8"
    },
    "id": "b7c476ad-67ec-494f-8d20-538453260a8c",
    "version": 3
  },
  "password": "8N3xRXnuP4u6DdGaRR8CMBkjFCD6PCHn",
  "secretkey": "f0bee2ddbfbe7792f31a77906a1e4b379be1fb6d5376f01645f173866d254767",
  "mnemonic": "syrup session ill fetch same river joy expose index voyage forget fog tent pumpkin hard domain neck happy cloud give canal priority sample fish",
  "address": "0x65ad46610b0d90686a79b36b5fd476f63b9997c6"
}
```

Metamask interoperability
-------------------------
The `secretkey` 64 letter hex value can be used to import wallet into Metamask,
as described in the [docs](https://support.metamask.io/hc/en-us/articles/360015489331-How-to-import-an-account#h_01G01W07NV7Q94M7P1EBD5BYM4)
