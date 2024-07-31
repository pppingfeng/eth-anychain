use std::{convert::TryFrom, fmt::Display};

pub(crate) enum ChainType{
    Ethereum,
    Goerli,
    Sepolia,
    EthereumClassic,
    
}

#[derive(Debug,Error)]
pub enum ChainTypeError{
    UnknownType(u32),
}
impl Display for ChainTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownType(code) => write!(f, "unknown chain type :{}", code),
        }
    }
}
impl TryFrom<u32> for ChainType {
    fn try_from(type_code: u32) -> Result<Self, Self::Error> {
        match type_code {
            60 => Ok(Self::Ethereum),                   // chain id = 1
            6001 => Ok(Self::Goerli),                   // chain id = 5
            6002 => Ok(Self::Sepolia),                  // chain id = 11155111
            61 => Ok(Self::EthereumClassic),            // chain id = 61
            _ => Err(ChainTypeError::UnknownType(type_code)),
        }
    }
    type Error = ChainTypeError;
}
