use commonware_codec::Encode;
use nunchi_coins::{Address, CoinId, CoinOperation, PrivateKey, Transaction};
use nunchi_crypto::PublicKey;

fn main() {
    let seeds = [1u64, 7, 42];

    println!("# Nunchi Wallet Test Fixtures");
    println!();
    println!("These fixtures verify that the WASM crypto produces byte-identical");
    println!("encodings and addresses matching the Rust implementation.");
    println!();

    for seed in seeds {
        let private = PrivateKey::from_seed(seed);
        let public = private.public_key();
        let address = Address::external(&public);

        println!("## Seed {}", seed);
        println!("Private Key (hex): {}", hex::encode(private.encode()));
        println!("Public Key (hex):  {}", hex::encode(public.encode()));
        println!("Address (bech32):  {}", address.to_bech32());
        println!();
    }

    println!("## Transaction Signing");
    let private = PrivateKey::from_seed(1);
    let from = Address::external(&private.public_key());
    let to = Address::external(&PrivateKey::from_seed(2).public_key());
    let coin = CoinId::decode(&[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]).unwrap();

    let transaction = Transaction::sign(
        &private,
        0,
        CoinOperation::Transfer {
            coin,
            from: from.clone(),
            to: to.clone(),
            amount: 1000,
        },
    );

    println!("From:         {}", from.to_bech32());
    println!("To:           {}", to.to_bech32());
    println!("Coin:         {}", hex::encode(&coin));
    println!("Amount:       1000");
    println!("Nonce:        0");
    println!("Tx (hex):     {}", hex::encode(transaction.encode()));
    println!("Digest (hex): {}", hex::encode(transaction.digest()));
}

use commonware_codec::{DecodeExt, Error};

trait CoinIdExt {
    fn decode(bytes: &[u8]) -> Result<CoinId, Error>;
}

impl CoinIdExt for CoinId {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        CoinId::decode(bytes)
    }
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(bytes: T) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
