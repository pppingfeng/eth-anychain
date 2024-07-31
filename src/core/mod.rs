use chain_type::ChainType;
use anychain_core::{Address, PublicKey};
use anychain_ethereum::{
    Ethereum, EthereumAddress, EthereumClassic, EthereumFormat,
    EthereumPublicKey, Goerli,Sepolia,
};
use anychain_kms::{
    bip32::{
        ChildNumber, DerivationPath, ExtendedKey, ExtendedKeyAttrs, HmacSha512, Prefix,
        XprvSecp256k1, XpubSecp256k1,
    },
    bip39::{Language, Mnemonic, MnemonicType, Seed},
    crypto::ripemd,
};
use anyhow::{anyhow, Result};
use digest::Mac;
use libaes::Cipher;
use rand::thread_rng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{str::FromStr, time::SystemTime};

mod eth;
mod chain_type;
mod util;

/**
 * 创建助记词
 * argument 0: lang, 语言类型，可选值: en, zh-cn
 * argument 1: word_count, 单词数量，可选值: 12, 15, 18, 21, 24
 */
pub fn create_mnemonic(lang_code: String, size: u8) -> Result<Value> {
    let word_count = MnemonicType::for_word_count(size.into())?;
    let language = Language::from_language_code(lang_code.as_str())
        .ok_or(anychain_kms::bip39::ErrorKind::InvalidWord)?;
    let mnemonic = Mnemonic::new(word_count, language);
    Ok(Value::String(mnemonic.phrase().to_string()))
}

/**
 * 解析助记词获取钱包属性
 * phrase: 助记词
 * return {"hash": "wallet_hash_id", "xpub": "主扩展公钥"}
 */
pub fn parse_mnemonic(phrase: String) -> Result<Value> {
    if let Some(language) = Language::from_phrase(phrase.as_str()) {
        Mnemonic::validate(phrase.as_str(), language)?;
        let mut seed = Vec::<u8>::new();
        let mnemonic = Mnemonic::from_phrase(phrase.as_str(), language)?;
        seed.extend_from_slice(Seed::new(&mnemonic, "").as_bytes());
        let hash = ripemd(&seed);
        let xprv = XprvSecp256k1::new(seed)?;
        let xpub = xprv.public_key().to_string(Prefix::XPUB);
        let data = json!({
            "xpub": xpub,
            "hash": hash,
        });
        Ok(data)
    } else {
        Err(anyhow::Error::msg("invalid phrase"))
    }
}

pub fn generate_master_xpub(public_key: String, chain_code: String) -> Result<Value> {
    let pk = serde_json::from_str::<Value>(&public_key)?;
    let pk = pk.as_array().unwrap();
    let pk: Vec<u8> = pk.iter().map(|byte| byte.as_u64().unwrap() as u8).collect();

    let cc = hex::decode(chain_code)?;

    if pk.len() != 33 {
        return Err(anyhow!("Invalid public key length"));
    }
    if cc.len() != 32 {
        return Err(anyhow!("Invalid chain code length"));
    }

    let mut key_bytes = [0u8; 33];
    let mut chain_code = [0u8; 32];

    chain_code.copy_from_slice(&cc);
    key_bytes.copy_from_slice(&pk);

    let attrs = ExtendedKeyAttrs {
        depth: 0,
        parent_fingerprint: [0u8; 4],
        chain_code,
        child_number: ChildNumber(0),
    };

    let xpub = ExtendedKey {
        prefix: Prefix::XPUB,
        attrs,
        key_bytes,
    };

    Ok(Value::String(
        XpubSecp256k1::try_from(xpub)?.to_string(Prefix::XPUB),
    ))
}

pub fn create_address(xpub: String, chain_type: u32, index1: u32, index2: u32, format: String) -> Result<Value> {
    let path = format!("m/44/{}/0/{}/{}", chain_type, index1, index2);
    let chain_type = ChainType::try_from(chain_type)?;
    let xpub = XpubSecp256k1::from_str(xpub.as_str())?;
    let derive_path = DerivationPath::from_str(path.as_str())?;
    let pubkey = *xpub.derive_from_path(&derive_path)?.public_key();
            match chain_type {
                ChainType::Ethereum
                | ChainType::Goerli
                | ChainType::Sepolia
                | ChainType::EthereumClassic => {
                    let address = EthereumPublicKey::from_secp256k1_public_key(pubkey)
                        .to_address(&EthereumFormat::Standard)?;
                    Ok(Value::String(address.to_string().to_lowercase()))
                }
            }
    }


/// Returns the messages of the transaction for signing
pub fn generate_signing_messages(chain_type: u32, tx: String, reserved: String) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Ethereum => eth::generate_signing_messages::<Ethereum>(tx),
        ChainType::Goerli => eth::generate_signing_messages::<Goerli>(tx),
        ChainType::Sepolia => eth::generate_signing_messages::<Sepolia>(tx),
        ChainType::EthereumClassic => eth::generate_signing_messages::<EthereumClassic>(tx),

    }
    }

/// Insert the given signatures into the transaction parameter and return
/// the final signed transaction stream to be broadcasted
pub fn insert_signatures(
    signatures: String,
    chain_type: u32,
    tx: String,
    reserved: String,
) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Ethereum => eth::insert_signatures::<Ethereum>(signatures, tx),
        ChainType::Goerli => eth::insert_signatures::<Goerli>(signatures, tx),
        ChainType::Sepolia => eth::insert_signatures::<Sepolia>(signatures, tx),
        ChainType::EthereumClassic => eth::insert_signatures::<EthereumClassic>(signatures, tx),
        
    }
}

/// Decode the raw transaction byte stream to human-readable json object
pub fn decode_raw_transaction(raw_tx: String, chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Ethereum => eth::decode_raw_transaction::<Ethereum>(raw_tx),
        ChainType::Goerli => eth::decode_raw_transaction::<Goerli>(raw_tx),
        ChainType::Sepolia => eth::decode_raw_transaction::<Sepolia>(raw_tx),
        ChainType::EthereumClassic => eth::decode_raw_transaction::<EthereumClassic>(raw_tx),

    }
}

pub fn verify_address(address: String, chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;
    let is_valid = match chain_type {
        ChainType::Ethereum
        | ChainType::Goerli
        | ChainType::Sepolia
        | ChainType::EthereumClassic => EthereumAddress::is_valid(&address),
    };
    Ok(Value::Bool(is_valid))
}


pub fn transaction_parameters_use_case(chain_type: u32) -> Result<Value> {
    let chain_type = ChainType::try_from(chain_type)?;

    match chain_type {
        ChainType::Ethereum
        | ChainType::Goerli
        | ChainType::Sepolia
        | ChainType::EthereumClassic => Ok(Value::String(eth::tx_params_json())),
    }
}

pub fn keygen() -> Result<Value> {
    let mut rng = thread_rng();
    let sk = libsecp256k1::SecretKey::random(&mut rng);
    let pk = libsecp256k1::PublicKey::from_secret_key(&sk);
    let sk = sk.serialize().to_vec();
    let pk = pk.serialize_compressed().to_vec();
    let sk_hex = hex::encode(&sk);
    let skhash = ripemd(sk_hex.as_bytes());
    let sk = hex::encode(&sk);
    let pk = hex::encode(&pk);

    Ok(json!({
        "secret_key": sk,
        "public_key": pk,
        "secret_key_hash": skhash
    }))
}

pub fn sign(data: &str, sk: &str) -> Result<Value> {
    let sk = hex::decode(&sk)?;
    let sk = libsecp256k1::SecretKey::parse_slice(&sk)?;

    let elapsed_minutes = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        / 60
        / 30;

    let msg = hmac_digest(data, elapsed_minutes)?;
    let msg = libsecp256k1::Message::parse_slice(&msg)?;

    let sig = libsecp256k1::sign(&msg, &sk).0;
    let sig = sig.serialize().to_vec();
    let sig = hex::encode(&sig);

    Ok(Value::String(sig))
}

pub fn verify(data: &str, signature: &str, pk: &str) -> Result<Value> {
    let elapsed_half_hours = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs()
        / 60
        / 30;

    match do_verify(data, signature, pk, elapsed_half_hours) {
        Ok(true) => Ok(Value::Bool(true)),
        // case when the time has reached the next half-hour of the signing moment
        Ok(false) => match do_verify(data, signature, pk, elapsed_half_hours - 1) {
            Ok(t) => Ok(Value::Bool(t)),
            Err(e) => Err(anyhow!("{}", e)),
        },
        Err(e) => Err(anyhow!("{}", e)),
    }
}

pub fn hash(data: &str) -> Result<Value> {
    Ok(Value::String(ripemd(data.as_bytes())))
}

pub fn encrypt(data: &str, secret_key: &str) -> Result<Value> {
    let data = data.as_bytes();
    let (key, iv) = key_and_iv(secret_key)?;
    let cipher = Cipher::new_128(&key);
    let data = cipher.cbc_encrypt(&iv, &data);
    Ok(Value::String(hex::encode(&data)))
}

pub fn decrypt(data: &str, secret_key: &str) -> Result<Value> {
    let data = hex::decode(data)?;
    let (key, iv) = key_and_iv(secret_key)?;
    let cipher = Cipher::new_128(&key);
    let data = cipher.cbc_decrypt(&iv, &data);
    Ok(Value::String(String::from_utf8(data)?))
}

pub fn json_digest(json: &str) -> Result<Value> {
    let val = serde_json::from_str::<Value>(json)?;
    let stream = serialize_json(&val);
    let hash = ripemd(stream.as_bytes());
    Ok(Value::String(hash))
}

fn serialize_json(val: &Value) -> String {
    match val {
        Value::Null => "".to_string(),
        Value::Bool(b) => format!("{}", b),
        Value::Number(n) => format!("{}", n),
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            let mut ret = String::new();
            for elem in arr {
                ret = format!("{}{}", ret, serialize_json(elem));
            }
            ret
        }
        Value::Object(map) => {
            let mut ret = String::new();
            for (key, value) in map {
                ret = format!("{}{}{}", ret, key, serialize_json(value));
            }
            ret
        }
    }
}

fn do_verify(data: &str, signature: &str, pk: &str, elapsed_half_hours: u64) -> Result<bool> {
    let msg = hmac_digest(data, elapsed_half_hours)?;
    let msg = libsecp256k1::Message::parse_slice(&msg)?;
    let sig = hex::decode(&signature)?;
    let sig = libsecp256k1::Signature::parse_standard_slice(&sig)?;
    let pk = hex::decode(pk)?;
    let pk = libsecp256k1::PublicKey::parse_slice(&pk, None)?;
    Ok(libsecp256k1::verify(&msg, &sig, &pk))
}

fn hmac_digest(data: &str, elapsed_half_hours: u64) -> Result<Vec<u8>> {
    let data = data.as_bytes();

    let key = [
        elapsed_half_hours.to_le_bytes().to_vec(), // elapsed half-hours is of type u64, which is 8 bytes
        vec![0; 24],                               // pad 24 zeros to form the key for HmacSha512
    ]
    .concat();

    let mut hasher = HmacSha512::new_from_slice(&key)?;
    hasher.update(&data);

    let hash = hasher.finalize().into_bytes();
    let (msg, _) = hash.split_at(32);
    let msg = msg.to_vec();
    Ok(msg)
}

fn key_and_iv(secret_key: &str) -> Result<([u8; 16], [u8; 16])> {
    let sk = hex::decode(secret_key)?;
    let skhash = Sha256::digest(&sk);
    let mut key: [u8; 16] = [0; 16];
    let mut iv: [u8; 16] = [0; 16];

    let mut j = 0;
    let mut k = 0;
    for i in 0..skhash.len() {
        if i % 2 == 0 {
            key[j] = skhash[i];
            j += 1;
        } else {
            iv[k] = skhash[i];
            k += 1;
        }
    }

    Ok((key, iv))
}