use rand::thread_rng;
use secp256k1zkp::{key::PublicKey, key::SecretKey, ContextFlag, Message, Secp256k1, Signature};

fn main() {
    let secp = Secp256k1::with_caps(ContextFlag::SignOnly);
    let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();
    let sk_string = sk.to_hex();
    let pk_string = pk.to_hex();
    println!("sk: {}", sk_string);
    println!("pk: {}", pk_string);

    assert_eq!(SecretKey::from_hex(sk_string).unwrap(), sk);
    assert_eq!(PublicKey::from_hex(pk_string).unwrap(), pk);
}
