use axum::{RequestPartsExt, extract::FromRequestParts, http::request::Parts};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use base64::prelude::*;

use crate::{error::APIError, state::TokenManager};

pub struct Token {
    pub user_id: i64,
    pub nonce: [u8; 32],
}

impl Token {
    // Tokenを扱う際の最初に実行される。こいつを実行するとnonceが生成される。
    pub async fn new<S: TokenManager>(user_id: i64, state: &S) -> anyhow::Result<Self> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce)?;
        let token = Self { user_id, nonce };
        state
            .create_token(token.get_nonce_as_string(), user_id)
            .await?;
        Ok(token)
    }

    // Tokenを生成する。stateに保存も行う。
    pub async fn generate(&self) -> anyhow::Result<String> {
        let mut buffer = [0; 41];
        buffer[..8].copy_from_slice(&self.user_id.to_be_bytes());
        buffer[8] = b'.';
        buffer[9..].copy_from_slice(&self.nonce);
        Ok(BASE64_URL_SAFE_NO_PAD.encode(buffer))
    }

    // Tokenをパースする。stateの確認は行わない。
    pub fn parse(token: String) -> anyhow::Result<Self> {
        let buffer = BASE64_URL_SAFE_NO_PAD.decode(token.as_bytes())?;
        let mut user_id_bytes = [0u8; 8];
        user_id_bytes.copy_from_slice(&buffer[..8]);
        let user_id = i64::from_be_bytes(user_id_bytes);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&buffer[9..]);
        Ok(Self { user_id, nonce })
    }

    // nonceをbase64エンコードした文字列を返す。
    pub fn get_nonce_as_string(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.nonce)
    }
}

impl<S> FromRequestParts<S> for Token
where
    S: TokenManager,
{
    type Rejection = APIError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| APIError::unauthorized("Missing authorization header"))?;

        let token = Token::parse(bearer.token().to_string())?;

        let nonce = token.get_nonce_as_string();

        if !state.exist_token(nonce, token.user_id).await? {
            return Err(APIError::unauthorized("Invalid token"));
        }

        Ok(token)
    }
}
