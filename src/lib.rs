use std::io::{Read, Write};

use num_bigint::{BigUint, RandBigInt};
use rand::prelude::*;

use openssl::{base64, sha, symm};

fn get_g() -> BigUint {
    BigUint::parse_bytes(b"CE369E8F9F2B0F43C0E837CCEC78439B97FF11D2E8DD3DDC57836F8DE11DF848D1CF99615C23BAA3BCF87D9D5DDDE981CFA885647780FEFA21CB07265561AF679BA170E9547E125ECC7B340DCAC3D9F6BF38AF243B01125D1CB0ADCDD80024A235CF25B8ABD5DAEC18AE0E063673DAE2DBFB416AF60E1233320490E1218DA5AD16C91527076E36A7DA9623715428F80010BB9F30477BFCC89F3183D343184A18E938CAB6EF364BE069FA7BE251AA267C6BFE62F247AC1A72BE7830EDB769E195E3CD6BB13DD684FE10DD9C042A465ADF46E0C5EF6458D0304DEE3437B940C904B235DB669A4013198A8184AE7F060F903EAFAB3150E24C011CBE57FAD7BAA1B62DEFB53B2DF0F51019DC339D2D25AA00F904E1AA17E1005B", 16).unwrap()
}

pub fn alice() {
    let g = get_g();
    let xa_lower = thread_rng().gen_biguint_below(&g);

    generate_x(&g, &xa_lower, "XA");

    let key = generate_master_key(&g, &xa_lower, "XB");
    let ca = generate_16_bytes();

    generate_e_one(&key, ca);
    check_e_two(&key, ca);
}

pub fn bob() {
    let g = get_g();
    let xb_lower = thread_rng().gen_biguint_below(&g);

    generate_x(&g, &xb_lower, "XB");

    let key = generate_master_key(&g, &xb_lower, "XA");
    let cb = generate_16_bytes();

    generate_e_two(&key, cb);
    check_e_three(&key, cb);
}

fn generate_x(g: &BigUint, generated_x: &BigUint, label: &str) {
    let pi = get_bytes_from_terminal("Password");

    let f_pi = sha::sha256(&pi);
    let f_pi_number = BigUint::from_bytes_be(&f_pi);

    let x = f_pi_number.modpow(generated_x, &g);
    let x_bytes = x.to_bytes_be();

    println!("{} < {}", label, base64::encode_block(&x_bytes));
}

fn generate_master_key(g: &BigUint, x_lower: &BigUint, label: &str) -> [u8; 32] {
    let x = get_bytes_from_terminal(label);
    let x = String::from_utf8_lossy(&x);
    let x = base64::decode_block(&x).unwrap();

    let x_number = BigUint::from_bytes_be(&x);
    let x_pow_x_lower = x_number.modpow(&x_lower, &g);

    sha::sha256(&x_pow_x_lower.to_bytes_be())
}

fn generate_e_one(key: &[u8], ca: [u8; 16]) {
    let iv = generate_16_bytes();

    let e_one = crypt_with_aes(key, &iv, &ca, symm::Mode::Encrypt);

    println!("E1 < {}", base64::encode_block(&e_one));
}

fn generate_e_two(key: &[u8], cb: [u8; 16]) {
    let e_one = get_bytes_from_terminal("E1");
    let e_one = String::from_utf8_lossy(&e_one);
    let e_one = base64::decode_block(&e_one).unwrap();

    let iv = &e_one[0..16];
    let e_one = &e_one[16..32];

    let mut ca = crypt_with_aes(key, iv, e_one, symm::Mode::Decrypt);
    let mut cb = cb.to_vec();
    cb.append(&mut ca);

    let iv = generate_16_bytes();

    let e_two = crypt_with_aes(key, &iv, &cb, symm::Mode::Encrypt);

    println!("E2 < {}", base64::encode_block(&e_two));
}

fn check_e_two(key: &[u8], ca: [u8; 16]) {
    let e_two = get_bytes_from_terminal("E2");
    let e_two = String::from_utf8_lossy(&e_two);
    let e_two = base64::decode_block(&e_two).unwrap();

    let iv = &e_two[0..16];
    let e_two = &e_two[16..48];

    let plaintext = crypt_with_aes(key, iv, e_two, symm::Mode::Decrypt);

    let cb = &plaintext[0..16];
    let other_ca = plaintext[16..32].to_vec();

    if &other_ca == &ca[..] {
        let iv = generate_16_bytes();

        let e_three = crypt_with_aes(key, &iv, cb, symm::Mode::Encrypt);

        println!("E3 < {}", base64::encode_block(&e_three));

        println!("PASS");
        println!("Key: {}", base64::encode_block(key));
    } else {
        println!("FAIL");
    }
}

fn check_e_three(key: &[u8], cb: [u8; 16]) {
    let e_three = get_bytes_from_terminal("E3");
    let e_three = String::from_utf8_lossy(&e_three);
    let e_three = base64::decode_block(&e_three).unwrap();

    let iv = &e_three[0..16];
    let e_three = &e_three[16..32];

    let other_cb = crypt_with_aes(key, iv, e_three, symm::Mode::Decrypt);

    if &other_cb == &cb[..] {
        println!("PASS");
        println!("Key: {}", base64::encode_block(key));
    } else {
        println!("FAIL");
    }
}

fn generate_16_bytes() -> [u8; 16] {
    let mut bytes = [0; 16];

    for i in &mut bytes {
        *i = thread_rng().gen::<u8>();
    }

    bytes
}

fn get_bytes_from_terminal(label: &str) -> Vec<u8> {
    let mut buff = [0; 1024];

    print!("{} > ", label);
    std::io::stdout().flush().unwrap();
    let buff_len = std::io::stdin().read(&mut buff).unwrap();

    buff[..buff_len - 1].to_vec()
}

fn crypt_with_aes(key: &[u8], iv: &[u8], message: &[u8], mode: symm::Mode) -> Vec<u8> {
    let mut crypter =
        symm::Crypter::new(symm::Cipher::aes_256_cbc(), mode, key, Some(&iv)).unwrap();

    crypter.pad(false);

    let mut crypted_message = vec![0; 128];

    let mut count = crypter.update(&message, &mut crypted_message).unwrap();
    count += crypter.finalize(&mut crypted_message).unwrap();
    crypted_message.truncate(count);

    if let symm::Mode::Encrypt = mode {
        let mut encrypted_message = iv.to_vec();
        encrypted_message.append(&mut crypted_message);
        crypted_message = encrypted_message;
    }

    crypted_message
}
