#[cfg(feature = "server")]
use actix_web::{App, HttpServer, web};
#[cfg(feature = "server")]
use dotenv::dotenv;
#[cfg(feature = "server")]
use env_logger::Env;
#[cfg(feature = "server")]
use handlers::handlers::{process_operation, user_init_handler};
#[cfg(feature = "server")]
use log::info;
use stealth_error::StealthError;
// use utils::utils::user_encrypt_data;

pub mod enclave;
pub mod encryption;
pub mod handlers;
pub mod stealth_error;
pub mod types;
pub mod utils;

#[cfg(feature = "server")]
#[actix_web::main]
async fn main() -> Result<(), StealthError> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    dotenv().ok();

    let address: &str = "0.0.0.0:8080";
    info!("Starting stealth server at http://{}", address);

    HttpServer::new(move || App::new().configure(configure_routes))
        .bind(address)
        .map_err(|e| {
            StealthError::ServerInitializationError(format!("Failed to bind address: {}", e))
        })?
        .run()
        .await
        .map_err(|e| {
            StealthError::ServerInitializationError(format!("Failed to start server: {}", e))
        })
}

#[cfg(feature = "server")]
fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/userinit", web::get().to(user_init_handler))
        .route("/process", web::post().to(process_operation));
}
