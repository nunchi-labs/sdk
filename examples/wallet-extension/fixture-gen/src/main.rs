use nunchi_common::{Address, Authorization, Transaction, TransactionPayload};
use nunchi_crypto::PrivateKey;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::Hasher;

const COINS_NAMESPACE: &[u8] = b"_NUNCHI_COINS";

fn encode_transfer_operation(coin_id: &[u8], from: &Address, to: &Address, amount: u128) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(3);
    buf.extend_from_slice(coin_id);
    buf.extend_from_slice(from.encode().as_ref());
    buf.extend_from_slice(to.encode().as_ref());
    buf.extend_from_slice(&amount.encode());
    buf
}

fn main() {
    println!("=== Nunchi Wallet Extension Test Fixtures ===\n");

    let priv_key = PrivateKey::from_seed(42);
    let pub_key = priv_key.public_key();
    let address = Address::external(&pub_key);

    println!("Test Key (seed=42):");
    println!("  Private Key: {}", hex::encode(priv_key.encode()));
    println!("  Public Key:  {}", hex::encode(pub_key.encode()));
    println!("  Address:     {}", address.to_bech32());
    println!();

    let coin_id = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .expect("valid hex");
    let from = address.clone();
    let to_priv = PrivateKey::from_seed(99);
    let to_pub = to_priv.public_key();
    let to = Address::external(&to_pub);
    let amount = 1000u128;
    let nonce = 0u64;

    let operation = encode_transfer_operation(&coin_id, &from, &to, amount);
    let payload = TransactionPayload::new(nonce, operation);
    
    let signature = priv_key.sign(COINS_NAMESPACE, &{
        let mut bytes = Vec::new();
        bytes.extend_from_slice(address.encode().as_ref());
        bytes.push(0);
        bytes.extend_from_slice(&payload.nonce.encode());
        bytes.extend_from_slice(payload.operation.as_ref());
        bytes
    });
    
    let authorization = Authorization::Single {
        signer: Box::new(pub_key.clone()),
        signature,
    };
    
    let transaction = Transaction {
        account_id: address.clone(),
        payload,
        authorization,
    };

    let transaction_bytes = transaction.encode();
    let digest = commonware_cryptography::Sha256::hash(&transaction_bytes);

    println!("Test Transfer:");
    println!("  Nonce:       {}", nonce);
    println!("  Coin:        {}", hex::encode(&coin_id));
    println!("  From:        {}", from.to_bech32());
    println!("  To:          {}", to.to_bech32());
    println!("  Amount:      {}", amount);
    println!();
    println!("  Signed Tx:   {}", hex::encode(&transaction_bytes));
    println!("  Digest:      {}", hex::encode(digest.as_ref()));
    println!();

    let reimported = PrivateKey::decode(priv_key.encode().as_ref()).expect("reimport");
    let reimported_pub = reimported.public_key();
    let reimported_addr = Address::external(&reimported_pub);
    println!("Re-import Check:");
    println!("  Address matches: {}", reimported_addr.to_bech32() == address.to_bech32());
    println!();
}
