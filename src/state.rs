#[async_trait::async_trait]
pub trait TokenManager: Sync {
    /// Tokenの存在確認を行う。存在する場合はtrueを返す。
    /// Arguments:
    /// - nonce: ランダムな値
    /// - user_id: ユーザID
    async fn exist_token(&self, nonce: String, user_id: i64) -> anyhow::Result<bool>;
    /// Tokenを新規作成する。
    /// Arguments:
    /// - nonce: ランダムな値
    /// - user_id: ユーザID
    async fn create_token(&self, nonce: String, user_id: i64) -> anyhow::Result<()>;
}
