use std::io;
use rand::Rng;

fn power(a: i64, b: i64, p: i64) -> i64 {
    if b == 0 {
        return 1;
    }

    let half = power(a, b / 2, p);

    if b % 2 == 0 {
        half * half % p
    } else {
        a * half * half % p
    }
}


fn generate_private_key(p: i64) -> i64 {
    let mut rng = rand::rng();

    rng.random_range(1..p - 1)
}

fn mod_inverse(s: i64, p: i64) -> i64 {
    let mut inverse = 1;

    while s * inverse % p != 1 {
        inverse += 1;
    }

    inverse
}

fn encrypt(
    message: &str,
    g: i64,
    y: i64,
    p: i64,
) -> Vec<(i64, i64)> {

    let mut ciphertext = Vec::new();

    for byte in message.as_bytes() {

        let m = *byte as i64;

      
        let k = generate_private_key(p);

        let c1 = power(g, k, p);

        let c2 = m * power(y, k, p) % p;

        ciphertext.push((c1, c2));
    }

    ciphertext
}

fn decrypt(
    ciphertext: Vec<(i64, i64)>,
    x: i64,
    p: i64,
) -> Result<String, String> {

    let mut decrypted_bytes = Vec::new();

    for (c1, c2) in ciphertext {

        let s = power(c1, x, p);

        let inverse = mod_inverse(s, p);

        let m = c2 * inverse % p;

        decrypted_bytes.push(m as u8);
    }

    String::from_utf8(decrypted_bytes)
        .map_err(|_| "Invalid UTF-8 in decrypted message".to_string())
}

fn main() {

    let p = 257;
    let g = 3;

    let x = generate_private_key(p);

    let y = power(g, x, p);

    println!("Public Key: ({}, {}, {})", p, g, y);
    println!("Private Key: {}", x);

    println!("\nEnter message:");

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .unwrap();

    let message = input.trim();

    println!("Original Message: {}", message);

    let ciphertext = encrypt(
        message,
        g,
        y,
        p,
    );

    println!("\nCiphertext (HEX):");

    println!("C1:");

    for (c1, _) in &ciphertext {
        print!(" ({:02X})", c1);
    }

    println!();

    println!("C2:");

    for (_, c2) in &ciphertext {
        print!(" ({:02X})", c2);
    }

    println!();

    match decrypt(
        ciphertext,
        x,
        p,
    ) {
        Ok(decrypted) => {
            println!("\nDecrypted Message:");
            println!("{}", decrypted);
        }

        Err(error) => {
            println!("\nDecryption failed:");
            println!("{}", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const P: i64 = 257;
    const G: i64 = 3;

    fn keypair() -> (i64, i64) {
        let x = generate_private_key(P);

        (x, power(G, x, P))
    }

    #[test]
    fn round_trip() {
        let (x, y) = keypair();
        let msg = "hello, elgamal";

        let ct = encrypt(msg, G, y, P);

        assert_eq!(decrypt(ct, x, P).unwrap(), msg);
    }

    #[test]
    fn round_trip_covers_full_ascii_range() {
        let (x, y) = keypair();
        let msg: String = (0u8..=127).map(|b| b as char).collect();

        let ct = encrypt(&msg, G, y, P);

        assert_eq!(decrypt(ct, x, P).unwrap(), msg);
    }

    #[test]
    fn fresh_k_per_byte_repeated_bytes_do_not_collide() {
       
        let (_, y) = keypair();
        let msg = "a".repeat(200);

        let ct = encrypt(&msg, G, y, P);

        let distinct_c1: HashSet<i64> = ct.iter().map(|(c1, _)| *c1).collect();
        let distinct_pairs: HashSet<(i64, i64)> = ct.iter().cloned().collect();

        assert!(distinct_c1.len() > 50);
        assert!(distinct_pairs.len() > 50);
    }

    #[test]
    fn ciphertext_values_stay_in_the_field() {
        let (_, y) = keypair();

        for (c1, c2) in encrypt("range check", G, y, P) {
            assert!((1..P).contains(&c1));
            assert!((0..P).contains(&c2));
        }
    }

    #[test]
    fn generated_exponents_are_in_range() {
        for _ in 0..1000 {
            let k = generate_private_key(P);

            assert!((1..P - 1).contains(&k));
        }
    }

    #[test]
    fn power_matches_naive_exponentiation() {
        for b in 0..20 {
            let mut naive = 1i64;

            for _ in 0..b {
                naive = naive * G % P;
            }

            assert_eq!(power(G, b, P), naive);
        }
    }

    #[test]
    fn mod_inverse_is_correct() {
        for s in 1..P {
            assert_eq!(s * mod_inverse(s, P) % P, 1);
        }
    }
}