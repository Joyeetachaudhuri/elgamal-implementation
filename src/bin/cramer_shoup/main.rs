use num_bigint::BigUint;
use num_traits::One;
use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::fs;

struct PublicKey {
    p: BigUint,
    q: BigUint,
    g1: BigUint,
    g2: BigUint,
    c: BigUint,
    d: BigUint,
    h: BigUint,
}

struct SecretKey {
    x1: BigUint,
    x2: BigUint,
    y1: BigUint,
    y2: BigUint,
    z: BigUint,
}

struct Ciphertext {
    u1: BigUint,
    u2: BigUint,
    e: Vec<u8>,
    v: BigUint,
}

fn hex_to_biguint(s: &str) -> BigUint {
    let mut clean = String::new();

    for c in s.chars() {
        if !c.is_whitespace() {
            clean.push(c);
        }
    }

    BigUint::parse_bytes(clean.as_bytes(), 16)
        .expect("Invalid hexadecimal number")
}

fn power(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    a.modpow(b, p)
}

fn generate_private_key(q: &BigUint) -> BigUint {
    let mut rng = rand::rng();
    let bytes_len = q.to_bytes_be().len();

    loop {
        let mut bytes = vec![0u8; bytes_len];
        rng.fill(&mut bytes[..]);

        let value = BigUint::from_bytes_be(&bytes);

        if value >= BigUint::one() && value < *q {
            return value;
        }
    }
}

fn fixed_bytes(value: &BigUint, width: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();

    if bytes.len() >= width {
        return bytes;
    }

    let mut result = vec![0u8; width];

    result[width - bytes.len()..].copy_from_slice(&bytes);

    result
}

fn hash_value(
    u1: &BigUint,
    u2: &BigUint,
    e: &[u8],
    p: &BigUint,
    q: &BigUint,
) -> BigUint {
    let width = ((p.bits() + 7) / 8) as usize;

    let mut hasher = Sha3_256::new();

    hasher.update(fixed_bytes(u1, width));
    hasher.update(fixed_bytes(u2, width));

    hasher.update((e.len() as u64).to_be_bytes());
    hasher.update(e);

    let hash = hasher.finalize();

    BigUint::from_bytes_be(&hash) % q
}

fn kdf(
    shared_secret: &BigUint,
    u1: &BigUint,
    u2: &BigUint,
    p: &BigUint,
    label: &[u8],
    length: usize,
) -> Vec<u8> {
    let width = ((p.bits() + 7) / 8) as usize;

    let secret_bytes = fixed_bytes(shared_secret, width);
    let u1_bytes = fixed_bytes(u1, width);
    let u2_bytes = fixed_bytes(u2, width);

    let mut output = Vec::with_capacity(length);
    let mut counter = 0u32;

    while output.len() < length {
        let mut hasher = Sha3_256::new();

        hasher.update(label);
        hasher.update(&secret_bytes);
        hasher.update(&u1_bytes);
        hasher.update(&u2_bytes);
        hasher.update(counter.to_be_bytes());

        let block = hasher.finalize();

        output.extend_from_slice(&block);

        counter += 1;
    }

    output.truncate(length);

    output
}

fn keygen(
    p: BigUint,
    q: BigUint,
    g1: BigUint,
    g2: BigUint,
) -> std::io::Result<(PublicKey, SecretKey)> {
    let x1 = generate_private_key(&q);
    let x2 = generate_private_key(&q);
    let y1 = generate_private_key(&q);
    let y2 = generate_private_key(&q);
    let z = generate_private_key(&q);

    let c1 = power(&g1, &x1, &p);
    let c2 = power(&g2, &x2, &p);

    let c = (&c1 * &c2) % &p;

    let d1 = power(&g1, &y1, &p);
    let d2 = power(&g2, &y2, &p);

    let d = (&d1 * &d2) % &p;

    let h = power(&g1, &z, &p);

    let public_key = PublicKey {
        p: p.clone(),
        q: q.clone(),
        g1,
        g2,
        c,
        d,
        h,
    };

    let secret_key = SecretKey {
        x1,
        x2,
        y1,
        y2,
        z,
    };

    fs::write(
        "public_key.txt",
        format!(
            "p = {}\nq = {}\ng1 = {}\ng2 = {}\nc = {}\nd = {}\nh = {}\n",
            public_key.p,
            public_key.q,
            public_key.g1,
            public_key.g2,
            public_key.c,
            public_key.d,
            public_key.h
        ),
    )?;

    fs::write(
        "CS_secret_key.txt",
        format!(
            "x1={}\nx2={}\ny1={}\ny2={}\nz={}\n",
            secret_key.x1,
            secret_key.x2,
            secret_key.y1,
            secret_key.y2,
            secret_key.z
        ),
    )?;

    Ok((public_key, secret_key))
}

fn encrypt(
    message: &[u8],
    public_key: &PublicKey,
) -> Result<Ciphertext, String> {
    if message.is_empty() {
        return Err("Message cannot be empty".to_string());
    }

    let r = generate_private_key(&public_key.q);

    let u1 = power(
        &public_key.g1,
        &r,
        &public_key.p,
    );

    let u2 = power(
        &public_key.g2,
        &r,
        &public_key.p,
    );

    let shared_secret = power(
        &public_key.h,
        &r,
        &public_key.p,
    );

    let mask = kdf(
        &shared_secret,
        &u1,
        &u2,
        &public_key.p,
        b"CS-ENC",
        message.len(),
    );

    let e: Vec<u8> = message
        .iter()
        .zip(mask.iter())
        .map(|(m, k)| m ^ k)
        .collect();

    let alpha = hash_value(
        &u1,
        &u2,
        &e,
        &public_key.p,
        &public_key.q,
    );

    let cr = power(
        &public_key.c,
        &r,
        &public_key.p,
    );

    let alpha_r =
        (&alpha * &r) % &public_key.q;

    let d_alpha_r = power(
        &public_key.d,
        &alpha_r,
        &public_key.p,
    );

    let v = (&cr * &d_alpha_r) % &public_key.p;

    Ok(Ciphertext {
        u1,
        u2,
        e,
        v,
    })
}

fn validate_subgroup_element(
    value: &BigUint,
    public_key: &PublicKey,
) -> bool {
    if value <= &BigUint::one() || value >= &public_key.p {
        return false;
    }

    power(
        value,
        &public_key.q,
        &public_key.p,
    ) == BigUint::one()
}

fn decrypt(
    ciphertext: &Ciphertext,
    public_key: &PublicKey,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, String> {
    if ciphertext.e.is_empty() {
        return Err(
            "Empty ciphertext is not allowed".to_string()
        );
    }

    if !validate_subgroup_element(
        &ciphertext.u1,
        public_key,
    ) {
        return Err(
            "u1 is not a valid subgroup element".to_string()
        );
    }

    if !validate_subgroup_element(
        &ciphertext.u2,
        public_key,
    ) {
        return Err(
            "u2 is not a valid subgroup element".to_string()
        );
    }

    let alpha = hash_value(
        &ciphertext.u1,
        &ciphertext.u2,
        &ciphertext.e,
        &public_key.p,
        &public_key.q,
    );

    let alpha_y1 =
        (&alpha * &secret_key.y1)
        % &public_key.q;

    let exponent1 =
        (&secret_key.x1 + &alpha_y1)
        % &public_key.q;

    let alpha_y2 =
        (&alpha * &secret_key.y2)
        % &public_key.q;

    let exponent2 =
        (&secret_key.x2 + &alpha_y2)
        % &public_key.q;

    let part1 = power(
        &ciphertext.u1,
        &exponent1,
        &public_key.p,
    );

    let part2 = power(
        &ciphertext.u2,
        &exponent2,
        &public_key.p,
    );

    let expected_v =
        (&part1 * &part2) % &public_key.p;

    if expected_v != ciphertext.v {
        return Err(
            "Ciphertext verification failed".to_string()
        );
    }

    let shared_secret = power(
        &ciphertext.u1,
        &secret_key.z,
        &public_key.p,
    );

    let mask = kdf(
        &shared_secret,
        &ciphertext.u1,
        &ciphertext.u2,
        &public_key.p,
        b"CS-ENC",
        ciphertext.e.len(),
    );

    let message: Vec<u8> = ciphertext
        .e
        .iter()
        .zip(mask.iter())
        .map(|(c, k)| c ^ k)
        .collect();

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

    let g1 = g.clone();

    let t = generate_private_key(&q);

    let g2 = power(
        &g,
        &t,
        &p,
    );

    let (public_key, secret_key) =
        keygen(
            p,
            q,
            g1,
            g2,
        )
        .expect("Key generation failed");

    let message = fs::read("message.txt")
        .expect("Unable to read message.txt");

    println!("\nOriginal Message:");

    match String::from_utf8(message.clone()) {
        Ok(text) => println!("{}", text),
        Err(_) => println!("{:?}", message),
    }

    let mut ciphertext = encrypt(
        &message,
        &public_key,
    )
    .expect("Encryption failed");
   
    fs::write(
        "ciphertext.txt",
        format!(
            "u1 = {}\nu2 = {}\ne = {:02X?}\nv = {}\n",
            ciphertext.u1,
            ciphertext.u2,
            ciphertext.e,
            ciphertext.v
        ),
    )
    .expect("Unable to write ciphertext.txt");

    let decrypted_message = decrypt(
        &ciphertext,
        &public_key,
        &secret_key,
    )
    .expect("Decryption failed");

    println!("\nDecrypted Message:");

    match String::from_utf8(decrypted_message.clone()) {
        Ok(text) => println!("{}", text),
        Err(_) => println!("{:?}", decrypted_message),
    }

    fs::write(
        "decrypted_message.txt",
        &decrypted_message,
    )
    .expect(
        "Unable to write decrypted_message.txt"
    );
}