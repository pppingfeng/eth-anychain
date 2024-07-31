use super::util::get_signatures;
use anychain_core::Transaction;
use anychain_ethereum::{
    EthereumAddress, EthereumAmount, EthereumNetwork, EthereumTransaction, EthereumTransactionParameters
};
use anyhow::{anyhow, Result};
use ethereum_types::U256;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
struct ETHParams {
    #[serde(default)]
    contract: EthereumAddress,
    #[serde(default)]
    to: EthereumAddress,
    amount: String,
    nonce: Value,
    #[serde(rename = "gasPrice")]
    gas_price: String,
    #[serde(rename = "gasLimit")]
    gas_limit: String,
}

fn parse_tx<N: EthereumNetwork>(tx: String) -> Result<EthereumTransaction<N>> {
    let params: ETHParams = serde_json::from_str(&tx)?;

    let receiver: EthereumAddress;
    let amount: EthereumAmount;
    let gas = U256::from_dec_str(&params.gas_limit)?;
    let gas_price = EthereumAmount::from_wei(&params.gas_price)?;

    let nonce = match params.nonce {
        Value::Number(_) => U256::from(params.nonce.as_i64().unwrap() as i128),
        Value::String(s) => U256::from_dec_str(s.as_str()).unwrap(),
        _ => U256::from(0i128),
    };

    let data: Vec<u8>;


        receiver = params.to;
        amount = EthereumAmount::from_wei(&params.amount)?;
        data = vec![];

    Ok(EthereumTransaction::<N>::new(
        &EthereumTransactionParameters {
            receiver,
            amount,
            gas,
            gas_price,
            nonce,
            data,
        },
    )?)
}

pub fn generate_signing_messages<N: EthereumNetwork>(tx: String) -> Result<Value> {
    let tx = parse_tx::<N>(tx)?;
    let txid = tx.to_transaction_id()?;
    Ok(json!([hex::encode(txid.txid)]))
}

pub fn insert_signatures<N: EthereumNetwork>(signature: String, tx: String) -> Result<Value> {
    let sigs = get_signatures(signature, true)?;
    let mut tx = parse_tx::<N>(tx)?;
    let bytes = tx.sign(sigs[0][..64].to_vec(), sigs[0][64])?;
    Ok(json!(format!("0x{}", hex::encode(bytes))))
}

pub fn decode_raw_transaction<N: EthereumNetwork>(tx: String) -> Result<Value> {
    let tx = EthereumTransaction::<N>::from_str(&tx)?;
    let txid = format!("{}", tx.to_transaction_id()?);

    let transaction_call = match tx.parameters.decode_data() {
        std::result::Result::Ok(v) => v,
        std::result::Result::Err(_) => Value::Null,
    };

    let to = tx.parameters.receiver.to_string();
    let amount = tx.parameters.amount.to_string();
    let gas_limit = tx.parameters.gas.to_string();
    let gas_price = tx.parameters.gas_price.to_string();
    let nonce = tx.parameters.nonce.as_u32();

    let from = if let Some(from) = tx.sender {
        Value::String(from.to_string())
    } else {
        Value::Null
    };

    let signature = if let Some(sig) = tx.signature {
        let r = hex::encode(&sig.r);
        let s = hex::encode(&sig.s);
        let v: [u8; 4] = sig.v.try_into().unwrap();
        let v = u32::from_be_bytes(v);
        let recid = v - 2 * N::CHAIN_ID - 35;
        json!({
            "r": r,
            "s": s,
            "recid": recid,
        })
    } else {
        Value::Null
    };

    match transaction_call {
        Value::Null => Ok(json!({
            "type": "basic",
            "from": from,
            "to": to,
            "amount": amount,
            "gasLimit": gas_limit,
            "gasPrice": gas_price,
            "nonce": nonce,
            "signature": signature,
            "txid": txid,
        })),
        _ => Err(anyhow!("Illegal contract data")),
    }
}

/// Returns an example json string of ethereum transaction
/// parameters required from the user of this library
pub fn tx_params_json() -> String {
    let params = r#"
    json parameter format for ETH transactions is
    
    {
        "to": "0x69Fe38874455047c1FD71a2FCd336E14cB5Cf186",
        "amount": "5000000000000",
        "gasLimit": "21000",
        "gasPrice": "1000000000",
        "nonce": 1
    }
    "#;
    params.to_string()
}

#[cfg(test)]
mod tests {
    use super::decode_raw_transaction;
    use crate::core::eth::insert_signatures;
    use anychain_ethereum::Ethereum;

    #[test]
    fn test_tx_decode() {
        let tx = r#"{
        "to": "0x69Fe38874455047c1FD71a2FCd336E14cB5Cf186",
        "amount": "5000000000000",
        "gasLimit": "21000",
        "gasPrice": "1000000000",
        "nonce": 1
        }"#
        .to_string();

        let sig = r#"[{
            "r": "6a1cc03cd2ecb2997452447879431e78ee7772be2af5a042f04eef7f49a51893",
            "s": "1684eaad65ac3de3e67327a474c595f5d53abc1a30a63881b315b28d02c63f63",
            "recid": 1
        }]"#
        .to_string();

        let tx = insert_signatures::<Ethereum>(sig, tx).unwrap();
        let tx = tx.as_str().unwrap().to_string();
        // let tx = decode_raw_transaction::<Ethereum>(tx).unwrap();

        println!("{}", tx);
    }
}
