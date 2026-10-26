//! Prints the management TUI tabs as text (development aid).
//! `SSM_DATABASE_URL=... cargo run -p ssm-server --example tui_snapshot`

#[tokio::main]
async fn main() {
    let url = std::env::var("SSM_DATABASE_URL").expect("SSM_DATABASE_URL");
    let pool = sqlx::PgPool::connect(&url).await.expect("database");
    let state = ssm_server::AppState::new(pool);
    for tab in 0..5 {
        println!("{}\n", ssm_server::tui::snapshot(state.clone(), tab, 110, 26).await);
    }
}
