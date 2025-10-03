#[async_trait::async_trait]
pub trait TokenManager: Sync {
    async fn exist_token(&self, nonce: String, user_id: i64) -> anyhow::Result<bool>;
    async fn create_token(&self, nonce: String, user_id: i64) -> anyhow::Result<()>;
}
