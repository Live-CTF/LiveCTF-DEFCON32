use actix_web::{middleware, web, App, HttpServer};
use chrono::Duration;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use google_cloud_storage::client::Client;
use google_cloud_storage::client::ClientConfig;

mod actions;
mod challenges;
mod error;
mod exploits;
mod models;
mod ratelimit;

#[derive(Clone)]
struct AppState {
    admin_key: String,
    auth_server_url: String,
    auth_server_key: String,
    challenges_bucket: String,
    exploit_rate_limit: Duration,
    max_exploit_size: usize,
    scoring_parameters: common::models::ScoringParameters,
}

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let admin_key = std::env::var("ADMIN_KEY").expect("ADMIN_KEY not set");
    let amqp_addr = std::env::var("AMQP_ADDR").expect("AMQP_ADDR not set");
    let api_host = std::env::var("API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let api_port = std::env::var("API_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("API_PORT not set to an integer");
    let auth_server_key = std::env::var("AUTH_KEY").expect("AUTH_KEY not set");
    let auth_server_url = std::env::var("AUTH_URL").expect("AUTH_URL not set");
    let challenges_bucket = std::env::var("CHALLENGES_BUCKET").expect("CHALLENGES_BUCKET not set");
    let conn_spec = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let exploits_path = std::env::var("EXPLOITS_PATH").expect("EXPLOITS_PATH not set");
    let redis_host = std::env::var("REDIS_HOST").expect("REDIS_HOST not set");
    let storage_type = std::env::var("EXPLOITS_STORAGE").expect("EXPLOITS_STORAGE not set");

    let gcp_client = {
        let gcp_config = ClientConfig::default().with_auth().await.unwrap();
        let gcp_client = Client::new(gcp_config);
        web::Data::new(gcp_client)
    };

    let db_pool = {
        let db_pool = common::setup_database_pool(&conn_spec)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;

        web::Data::new(db_pool)
    };

    let redis_client = {
        let redis_client = redis::Client::open(redis_host)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
        web::Data::new(redis_client)
    };

    let amqp_pool = {
        let cfg = deadpool_lapin::Config {
            url: Some(amqp_addr),
            ..Default::default()
        };
        let pool = cfg
            .create_pool(Some(deadpool_lapin::Runtime::Tokio1))
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;

        let connection = pool
            .get()
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
        let channel = connection
            .create_channel()
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;
        channel
            .queue_declare(
                common::EXPLOIT_BUILD_QUEUE,
                lapin::options::QueueDeclareOptions::default(),
                lapin::types::FieldTable::default(),
            )
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, err))?;

        web::Data::new(pool)
    };

    let object_store = {
        let object_store = common::get_object_store(&storage_type, &exploits_path)?;
        web::Data::new(object_store)
    };

    let app_state = {
        // score = 50 - 1pt/6min => [10, 50]
        let scoring_parameters = common::models::ScoringParameters::quals2023();
        /*let hmac_key = Hmac::new_from_slice(hmac_key.as_bytes())
        .expect("Failed to initialize HMAC from HMAC_KEY");*/
        web::Data::new(AppState {
            //hmac_key,
            admin_key,
            auth_server_url,
            auth_server_key,
            challenges_bucket,
            exploit_rate_limit: Duration::seconds(60),
            max_exploit_size: 50_000_000, // 50mb,
            scoring_parameters,
        })
    };

    log::info!("Starting HTTP server at http://{}:{}", api_host, api_port);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(object_store.clone())
            .app_data(amqp_pool.clone())
            .app_data(db_pool.clone())
            .app_data(redis_client.clone())
            .app_data(gcp_client.clone())
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .service(challenges::challenges_service())
            .service(exploits::exploits_service())
    })
    .bind((api_host, api_port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    // TODO (P2): Tests?
}
