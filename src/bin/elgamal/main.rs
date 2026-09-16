use std::io;
use rand::Rng;


fn power(a: i64, b: i64, p: i64) -> i64 {
    if b == 0 {
        return 1;
    }

    let half = power(a, b / 2, p);

    if b % 2 == 0 {
        
        return half * half % p;
    } else {
        
        return a * half * half % p;
    }
}


fn generate_private_key(p: i64) -> i64 {
    let mut rng = rand::rng();

 
    rng.random_range(1..p - 1)
}

fn generate_K(p: i64) -> i64 {
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

    p: i64
) -> Vec<(i64, i64)> {

    let k = generate_K(p);
    let mut ciphertext = Vec::new();

    for byte in message.as_bytes() {

        
        let m = *byte as i64;

        
        let c1 = power(g, k, p);

        
        let c2 = m * power(y, k, p) % p;

        ciphertext.push((c1, c2));
    }

    ciphertext
}


fn decrypt(
    ciphertext: Vec<(i64, i64)>,
    x: i64,
    p: i64
) -> String {

    let mut decrypted_bytes = Vec::new();
    

    for (c1, c2) in ciphertext {

       
        let s = power(c1, x, p);

       
        let inverse = mod_inverse(s, p);

        
        let m = c2 * inverse % p;

        
        decrypted_bytes.push(m as u8);
    }

    String::from_utf8(decrypted_bytes).unwrap()
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

    
  let k:i64;

   
    let ciphertext = encrypt(
        message,
        g,
        y,
        
        p
    );

    
    println!("\nCiphertext (HEX):");

    for (c1, c2) in &ciphertext {

        print!(" c1 :({:02X})", c1);
        
    }
    println!();
    for (c1, c2) in &ciphertext {
        print!(" c2 :({:02X})", c2);
    }

    println!();

    
    let decrypted = decrypt(
        ciphertext,
        x,
        p
    );

    println!("\nDecrypted Message:");
    println!("{}", decrypted);
}