use axum::{
    Router,
    extract::{Query, State},
    routing::get,
};
use serde::Deserialize;
use sqlx::SqlitePool;
use tn23_auth::{Token, TokenManager};
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    pub db_pool: SqlitePool,
}

impl AppState {
    pub async fn new(database_url: &str) -> anyhow::Result<Self> {
        let db_pool = SqlitePool::connect(database_url).await?;
        Ok(Self { db_pool })
    }
}

#[async_trait::async_trait]
impl TokenManager for AppState {
    async fn exist_token(&self, nonce: String, user_id: i64) -> anyhow::Result<bool> {
        let rec = sqlx::query!(
            "SELECT COUNT(*) as count FROM tokens WHERE nonce = ? AND user_id = ?",
            nonce,
            user_id
        )
        .fetch_one(&self.db_pool)
        .await?;
        Ok(rec.count > 0)
    }

    async fn create_token(&self, nonce: String, user_id: i64) -> anyhow::Result<()> {
        sqlx::query!(
            "INSERT INTO tokens (nonce, user_id) VALUES (?, ?)",
            nonce,
            user_id
        )
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    user_id: i64,
}

async fn create_token(
    State(state): State<AppState>,
    Query(params): Query<CreateTokenRequest>,
) -> tn23_auth::APIResult<String> {
    let token = Token::new(params.user_id, &state).await?;
    let token_str = token.generate().await?;
    println!("Generated token: {}", token_str);
    Ok(token_str)
}

async fn verify_token(token: Token) -> tn23_auth::APIResult<String> {
    Ok(format!("Token is valid for user_id: {}", token.user_id))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let state = AppState::new(&std::env::var("DATABASE_URL")?).await?;
    let app = Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .route("/create", get(create_token))
        .route("/verify", get(verify_token))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
