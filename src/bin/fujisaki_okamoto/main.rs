use std::fs;

use num_bigint::BigUint;
use num_traits::One;
use rand::RngCore;
use sha3::{Digest, Sha3_256};

struct PublicKey {
    h: BigUint,
}

struct SecretKey {
    x: BigUint,
}

struct Ciphertext {
    c1: BigUint,
    c2: Vec<u8>,
    c3: Vec<u8>,
}

fn hex_to_biguint(hex: &str) -> BigUint {
    let mut cleaned = String::new();

    for c in hex.chars() {
        if !c.is_whitespace() {
            cleaned.push(c);
        }
    }

    BigUint::parse_bytes(cleaned.as_bytes(), 16)
        .expect("Invalid hexadecimal number")
}

fn generate_private_key(q: &BigUint) -> BigUint {
    let mut rng = rand::rng();

    let bytes_len = q.to_bytes_be().len();

    loop {
        let mut bytes = vec![0u8; bytes_len];

        rng.fill_bytes(&mut bytes);

        let x = BigUint::from_bytes_be(&bytes);

        if x >= BigUint::one() && x < *q {
            return x;
        }
    }
}

fn keygen(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> Result<(PublicKey, SecretKey), String> {
    let x = generate_private_key(q);

    let h = g.modpow(&x, p);

    let public_key = PublicKey {
        h: h.clone(),
    };

    let secret_key = SecretKey {
        x: x.clone(),
    };

    fs::write(
        "FO_public_key.txt",
        format!(
            "q = {}\ng = {}\nh = {}\n",
            q,
            g,
            h
        ),
    )
    .map_err(|e| e.to_string())?;

    fs::write(
        "FO_secret_key.txt",
        format!(
            "x = {}\n",
            x
        ),
    )
    .map_err(|e| e.to_string())?;

    Ok((public_key, secret_key))
}

fn hash_sigma_message(
    sigma: &[u8],
    message: &[u8],
    q: &BigUint,
) -> BigUint {
    let mut hasher = Sha3_256::new();

    hasher.update(b"FO-HASH");

    hasher.update((sigma.len() as u64).to_be_bytes());
    hasher.update(sigma);

    hasher.update((message.len() as u64).to_be_bytes());
    hasher.update(message);

    let hash = hasher.finalize();

    let value = BigUint::from_bytes_be(&hash) % q;

    if value == BigUint::from(0u32) {
        BigUint::from(1u32)
    } else {
        value
    }
}

fn kdf(
    shared_secret: &BigUint,
    label: &[u8],
    length: usize,
) -> Vec<u8> {
    let mut output = Vec::new();

    let secret_bytes = shared_secret.to_bytes_be();

    let mut counter: u32 = 0;

    while output.len() < length {
        let mut hasher = Sha3_256::new();

        hasher.update(label);

        hasher.update((secret_bytes.len() as u64).to_be_bytes());
        hasher.update(&secret_bytes);

        hasher.update(counter.to_be_bytes());

        let hash = hasher.finalize();

        output.extend_from_slice(&hash);

        counter += 1;
    }

    output.truncate(length);

    output
}

fn kdf_bytes(
    input: &[u8],
    label: &[u8],
    length: usize,
) -> Vec<u8> {
    let mut output = Vec::new();

    let mut counter: u32 = 0;

    while output.len() < length {
        let mut hasher = Sha3_256::new();

        hasher.update(label);

        hasher.update((input.len() as u64).to_be_bytes());
        hasher.update(input);

        hasher.update(counter.to_be_bytes());

        let hash = hasher.finalize();

        output.extend_from_slice(&hash);

        counter += 1;
    }

    output.truncate(length);

    output
}

fn xor_bytes(
    message: &[u8],
    key: &[u8],
) -> Vec<u8> {
    let mut result = Vec::with_capacity(message.len());

    for i in 0..message.len() {
        result.push(message[i] ^ key[i]);
    }

    result
}

fn validate_subgroup_element(
    value: &BigUint,
    p: &BigUint,
    q: &BigUint,
) -> bool {
    if value == &BigUint::from(0u32) {
        return false;
    }

    if value >= p {
        return false;
    }

    value.modpow(q, p) == BigUint::one()
}

fn encrypt(
    message: &[u8],
    public_key: &PublicKey,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> Result<Ciphertext, String> {
    if message.is_empty() {
        return Err("Message cannot be empty".to_string());
    }

    let mut sigma = vec![0u8; 32];

    let mut rng = rand::rng();

    rng.fill_bytes(&mut sigma);

    let r = hash_sigma_message(
        &sigma,
        message,
        q,
    );

    let c1 = g.modpow(
        &r,
        p,
    );

    let shared_secret = public_key.h.modpow(
        &r,
        p,
    );

    let sigma_mask = kdf(
        &shared_secret,
        b"FO-SIGMA",
        sigma.len(),
    );

    let c2 = xor_bytes(
        &sigma,
        &sigma_mask,
    );

    let message_key = kdf_bytes(
        &sigma,
        b"FO-MESSAGE",
        message.len(),
    );

    let c3 = xor_bytes(
        message,
        &message_key,
    );

    Ok(Ciphertext {
        c1,
        c2,
        c3,
    })
}

fn decrypt(
    ciphertext: &Ciphertext,
    secret_key: &SecretKey,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> Result<Vec<u8>, String> {
    if !validate_subgroup_element(
        &ciphertext.c1,
        p,
        q,
    ) {
        return Err(
            "c1 is not a valid subgroup element".to_string()
        );
    }

    if ciphertext.c2.len() != 32 {
        return Err(
            "Invalid sigma ciphertext length".to_string()
        );
    }

    if ciphertext.c3.is_empty() {
        return Err(
            "Ciphertext message cannot be empty".to_string()
        );
    }

    let shared_secret = ciphertext.c1.modpow(
        &secret_key.x,
        p,
    );

    let sigma_mask = kdf(
        &shared_secret,
        b"FO-SIGMA",
        32,
    );

    let sigma = xor_bytes(
        &ciphertext.c2,
        &sigma_mask,
    );

    let message_key = kdf_bytes(
        &sigma,
        b"FO-MESSAGE",
        ciphertext.c3.len(),
    );

    let message = xor_bytes(
        &ciphertext.c3,
        &message_key,
    );

    let r_prime = hash_sigma_message(
        &sigma,
        &message,
        q,
    );

    let c1_prime = g.modpow(
        &r_prime,
        p,
    );

    if c1_prime != ciphertext.c1 {
        return Err(
            "Ciphertext verification failed".to_string()
        );
    }

    Ok(message)
}

fn main() {
    let p = hex_to_biguint(
        "87A8E61D B4B6663C FFBBD19C 65195999 8CEEF608 660DD0F2
         5D2CEED4 435E3B00 E00DF8F1 D61957D4 FAF7DF45 61B2AA30
         16C3D911 34096FAA 3BF4296D 830E9A7C 209E0C64 97517ABD
         5A8A9D30 6BCF67ED 91F9E672 5B4758C0 22E0B1EF 4275BF7B
         6C5BFC11 D45F9088 B941F54E B1E59BB8 BC39A0BF 12307F5C
         4FDB70C5 81B23F76 B63ACAE1 CAA6B790 2D525267 35488A0E
         F13C6D9A 51BFA4AB 3AD83477 96524D8E F6A167B5 A41825D9
         67E144E5 14056425 1CCACB83 E6B486F6 B3CA3F79 71506026
         C0B857F6 89962856 DED4010A BD0BE621 C3A3960A 54E710C3
         75F26375 D7014103 A4B54330 C198AF12 6116D227 6E11715F
         693877FA D7EF09CA DB094AE9 1E1A1597"
    );

    let q = hex_to_biguint(
        "8CF83642 A709A097 B4479976 40129DA2
         99B1A47D 1EB3750B A308B0FE 64F5FBD3"
    );

    let g = hex_to_biguint(
        "3FB32C9B 73134D0B 2E775066 60EDBD48 4CA7B18F
         21EF2054 07F4793A 1A0BA125 10DBC150 77BE463F
         FF4FED4A AC0BB555 BE3A6C1B 0C6B47B1 BC3773BF
         7E8C6F62 901228F8 C28CBB18 A55AE313 41000A65
         0196F931 C77A57F2 DDF463E5 E9EC144B 777DE62A
         AAB8A862 8AC376D2 82D6ED38 64E67982 428EBC83
         1D14348F 6F2F9193 B5045AF2 767164E1 DFC967C1
         FB3F2E55 A4BD1BFF E83B9C80 D052B985 D182EA0A
         DB2A3B73 13D3FE14 C8484B1E 052588B9 B7D2BBD2
         DF016199 ECD06E15 57CD0915 B3353BBB 64E0EC37
         7FD02837 0DF92B52 C7891428 CDC67EB6 184B523D
         1DB246C3 2F630784 90F00EF8 D647D148 D4795451
         5E2327CF EF98C582 664B4C0F 6CC41659"
    );

    let message = fs::read("message.txt")
        .expect("Unable to read message.txt");

    println!("\nOriginal Message:");

    match String::from_utf8(message.clone()) {
        Ok(text) => println!("{}", text),
        Err(_) => println!("{:?}", message),
    }

    let (public_key, secret_key) =
        keygen(
            &p,
            &q,
            &g,
        )
        .expect("Key generation failed");

    let ciphertext = encrypt(
        &message,
        &public_key,
        &p,
        &q,
        &g,
    )
    .expect("Encryption failed");

    let mut c2_hex = String::new();

    for b in &ciphertext.c2 {
        c2_hex.push_str(
            &format!("{:02x}", b)
        );
    }

    let mut c3_hex = String::new();

    for b in &ciphertext.c3 {
        c3_hex.push_str(
            &format!("{:02x}", b)
        );
    }

    fs::write(
        "FO_ciphertext.txt",
        format!(
            "c1 = {}\nc2 = {}\nc3 = {}\n",
            ciphertext.c1,
            c2_hex,
            c3_hex
        ),
    )
    .expect("Unable to write ciphertext file");

    let decrypted = decrypt(
        &ciphertext,
        &secret_key,
        &p,
        &q,
        &g,
    )
    .expect("Decryption failed");

    println!("\nDecrypted Message:");

    match String::from_utf8(decrypted.clone()) {
        Ok(text) => println!("{}", text),
        Err(_) => println!("{:?}", decrypted),
    }

    fs::write(
        "FO_decrypted_message.txt",
        &decrypted,
    )
    .expect("Unable to write decrypted message");

    println!("\nVerification: SUCCESS");
    println!("Ciphertext is valid.");
}