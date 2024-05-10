use std::sync::Arc;

use actix_multipart_extract::Multipart;
use actix_web::{get, post, web, HttpResponse};
use google_cloud_storage::sign::SignedURLOptions;
use object_store::ObjectStore;

use crate::actions;
use crate::models;

use crate::error::ApiError;
use crate::AppState;
use crate::DbPool;

pub fn challenges_service() -> actix_web::Scope {
    web::scope("/challenges")
        .service(get_challenges)
        .service(get_challenge)
        .service(download_challenge)
        .service(challenge_scores)
        .service(submit_exploit)
}

#[get("/")]
pub async fn get_challenges(pool: web::Data<DbPool>) -> Result<HttpResponse, ApiError> {
    let challenges = web::block(move || {
        let mut conn = pool.get()?;
        actions::get_released_challenges(&mut conn)
    })
    .await??;

    Ok(HttpResponse::Ok().json(challenges))
}

#[get("/{challenge_id}")]
pub async fn get_challenge(
    db_pool: web::Data<DbPool>,
    challenge_id: web::Path<common::models::ChallengeId>,
) -> Result<HttpResponse, ApiError> {
    let challenge_id = challenge_id.into_inner();

    let mut conn = db_pool.get()?;
    let challenge =
        web::block(move || actions::get_released_challenge(&mut conn, challenge_id)).await??;

    Ok(HttpResponse::Ok().json(challenge))
}

#[get("/{challenge_id}/download")]
pub async fn download_challenge(
    app_state: web::Data<AppState>,
    db_pool: web::Data<DbPool>,
    gcp_client: web::Data<google_cloud_storage::client::Client>,
    challenge_id: web::Path<common::models::ChallengeId>,
) -> Result<HttpResponse, ApiError> {
    let mut conn1 = db_pool.get()?;
    let challenge =
        web::block(move || actions::get_released_challenge(&mut conn1, *challenge_id)).await??;

    let url_for_download = gcp_client
        .signed_url(
            &app_state.challenges_bucket,
            &format!("{}.tgz", challenge.challenge_name()),
            None,
            None,
            SignedURLOptions::default(),
        )
        .await?;

    Ok(HttpResponse::Found()
        .insert_header(("Location", url_for_download))
        .finish())
}

#[get("/{challenge_id}/scores")]
pub async fn challenge_scores(
    app_state: web::Data<AppState>,
    db_pool: web::Data<DbPool>,
    challenge_id: web::Path<common::models::ChallengeId>,
) -> Result<HttpResponse, ApiError> {
    let app_state = app_state.into_inner();
    let mut conn = db_pool.get()?;
    let challenge_id = challenge_id.into_inner();

    let challenge = {
        let mut conn = db_pool.get()?;
        web::block(move || actions::get_released_challenge(&mut conn, challenge_id)).await??
    };

    let challenge_scores =
        common::get_challenge_scores(&mut conn, &challenge, &app_state.scoring_parameters)
            .await
            .expect("Failed to get challenge scores");

    Ok(HttpResponse::Ok().json(challenge_scores))
}

#[post("/{challenge_id}")]
pub async fn submit_exploit(
    app_state: web::Data<AppState>,
    amqp_pool: web::Data<deadpool_lapin::Pool>,
    db_pool: web::Data<DbPool>,
    object_store: web::Data<Arc<dyn ObjectStore>>,
    redis: web::Data<redis::Client>,
    challenge_id: web::Path<common::models::ChallengeId>,
    team_token: web::Header<models::AuthenticationTokenHeader>,
    exploit_form: Multipart<models::NewExploit>,
) -> Result<HttpResponse, ApiError> {
    let app_state = app_state.into_inner();
    let amqp_pool = amqp_pool.into_inner();
    let object_store = object_store.into_inner();

    let challenge_id = challenge_id.into_inner();
    let overwrite = exploit_form.overwrite.unwrap_or(false);
    let team_token = team_token.into_inner();

    let challenge = {
        let mut conn = db_pool.get()?;
        web::block(move || actions::get_open_challenge(&mut conn, challenge_id)).await??
    };

    let team_info = team_token
        .validate(
            &redis,
            &app_state.auth_server_url,
            &app_state.auth_server_key,
            Some(challenge.challenge_short_name()),
        )
        .await?;

    let valid_exploit_file = match actions::validate_submission_file(
        &exploit_form.exploit,
        app_state.max_exploit_size,
    ) {
        Ok(file) => file,
        Err(_) => {
            return Err(ApiError::ExploitFile {
                max_file_size: app_state.max_exploit_size,
            });
        }
    };

    if !crate::ratelimit::check_rate_limit(
        &redis,
        *team_info.team_id(),
        app_state.exploit_rate_limit,
    )
    .await?
    {
        return Err(ApiError::RateLimit {
            limit: app_state.exploit_rate_limit.num_seconds(),
        });
    };

    let mut conn = db_pool.get()?;
    match crate::actions::create_exploit_submission(
        &team_info,
        overwrite,
        valid_exploit_file,
        &challenge,
        &object_store,
        &mut conn,
        &amqp_pool,
    )
    .await
    .map_err(|error| match error {
        crate::actions::CreateExploitError::DbError(error) => ApiError::Database {
            error: error.to_string(),
        },
        crate::actions::CreateExploitError::MqError => ApiError::MessageQueue,
        crate::actions::CreateExploitError::ExploitAlreadyQueued {
            team_id,
            challenge_id,
        } => ApiError::ExploitAlreadyQueued {
            team_id,
            challenge_id,
        },
        crate::actions::CreateExploitError::FileSaveError(error) => ApiError::FileIO {
            error: error.to_string(),
        },
    }) {
        Err(err) => {
            crate::ratelimit::revert_rate_limit(
                &redis,
                *team_info.team_id(),
                app_state.exploit_rate_limit,
            )
            .await?;
            Err(err)
        }
        Ok(exploit) => Ok(HttpResponse::Ok().json(exploit)),
    }
}
