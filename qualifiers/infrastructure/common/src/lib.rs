pub mod models;
pub mod schema;

use diesel::PgConnection;
use diesel_migrations::MigrationHarness;

use object_store::aws::AmazonS3Builder;
use object_store::azure::MicrosoftAzureBuilder;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::local::LocalFileSystem;
use object_store::ObjectStore;

use std::sync::Arc;

use crate::models::ScoringModel;
use crate::models::ScoringParameters;
use crate::models::{Challenge, ChallengeId, Exploit, ExploitStatus};
use chrono::Utc;
use diesel::prelude::*;
use diesel::ExpressionMethods;

pub const EXPLOIT_BUILD_QUEUE: &str = "exploit-builds";
pub const EXPLOIT_RUN_QUEUE: &str = "exploit-runs";

const UNSCORED_SCORE: i32 = 1;

fn calculate_score(
    scoring_parameters: &ScoringParameters,
    first_solve: chrono::NaiveDateTime,
    scoring_time: chrono::NaiveDateTime,
) -> i32 {
    let elpased = scoring_time - first_solve;
    let elpased_periods: i32 = (elpased.num_seconds()
        / scoring_parameters.score_dropoff_period.num_seconds())
    .try_into()
    .unwrap_or(0);

    scoring_parameters.max_score - elpased_periods * scoring_parameters.score_dropoff
}

pub async fn get_challenge_scores(
    conn: &mut PgConnection,
    challenge: &Challenge,
    scoring_parameters: &ScoringParameters,
) -> Result<models::ChallengeScores, DbError> {
    match challenge.scoring_model() {
        // Normal score according to parameters
        ScoringModel::Normal => {
            get_challenge_scores_normal(conn, *challenge.challenge_id(), scoring_parameters).await
        }

        // No score
        ScoringModel::Unscored => {
            get_challenge_scores_unscored(conn, *challenge.challenge_id()).await
        }

        // Statically max score
        ScoringModel::Special1 => {
            get_challenge_scores_special1(conn, *challenge.challenge_id(), scoring_parameters).await
        }
    }
}

pub type DbError = Box<dyn std::error::Error + Send + Sync>;
pub async fn get_challenge_scores_normal(
    conn: &mut PgConnection,
    scores_challenge_id: ChallengeId,
    scoring_parameters: &ScoringParameters,
) -> Result<models::ChallengeScores, DbError> {
    use crate::schema::exploits::dsl::*;
    use diesel::dsl::not;

    let potential_solves = exploits
        .filter(
            challenge_id
                .eq(scores_challenge_id)
                .and(not(team_id.eq(23))) // TODO(P2): Replace this in the future with some flag on some team entity or something
                .and(
                    status
                        .eq(ExploitStatus::RunSolved)
                        .or(pending.eq(Some(true))),
                ),
        )
        .order(submission_time.asc())
        .load::<Exploit>(conn)?;

    let (next_score, solves) = match potential_solves.first() {
        // No potential solves yet
        None => (scoring_parameters.max_score, vec![]),
        // At least one potential solve
        Some(first_submission) => {
            let solves = potential_solves
                .iter()
                .filter(|exploit| *exploit.status() == ExploitStatus::RunSolved);

            // First potential solve is actual solve, we can start scoring
            if *first_submission.status() == ExploitStatus::RunSolved {
                let now = Utc::now().naive_utc();
                let score =
                    calculate_score(scoring_parameters, *first_submission.submission_time(), now);

                // Add calculated score to all solves
                let challenge_solves = solves
                    .map(|exploit| {
                        let score = calculate_score(
                            scoring_parameters,
                            *first_submission.submission_time(),
                            *exploit.submission_time(),
                        );
                        models::ChallengeSolve::new(
                            *exploit.exploit_id(),
                            *exploit.team_id(),
                            *exploit.submission_time(),
                            Some(score),
                            exploit.score_awarded().is_some(),
                        )
                    })
                    .collect();

                (score, challenge_solves)

            // First potential solve is still pending, we can't calculate scores yet
            } else {
                let score = scoring_parameters.max_score;

                // No scores for any submissions yet
                let challenge_solves = solves
                    .map(|exploit| {
                        models::ChallengeSolve::new(
                            *exploit.exploit_id(),
                            *exploit.team_id(),
                            *exploit.submission_time(),
                            None,
                            exploit.score_awarded().is_some(),
                        )
                    })
                    .collect();

                (score, challenge_solves)
            }
        }
    };

    Ok(models::ChallengeScores::new(
        scores_challenge_id,
        next_score,
        solves,
    ))
}

pub async fn get_challenge_scores_unscored(
    conn: &mut PgConnection,
    scores_challenge_id: ChallengeId,
) -> Result<models::ChallengeScores, DbError> {
    use crate::schema::exploits::dsl::*;
    use diesel::dsl::not;

    let solves = exploits
        .filter(
            challenge_id
                .eq(scores_challenge_id)
                .and(not(team_id.eq(23))) // TODO(P2): Replace this in the future with some flag on some team entity or something
                .and(status.eq(ExploitStatus::RunSolved)),
        )
        .order(submission_time.asc())
        .load::<Exploit>(conn)?;

    let next_score = 0;

    let challenge_solves = solves
        .iter()
        .map(|exploit| {
            models::ChallengeSolve::new(
                *exploit.exploit_id(),
                *exploit.team_id(),
                *exploit.submission_time(),
                Some(UNSCORED_SCORE),
                exploit.score_awarded().is_some(),
            )
        })
        .collect();

    Ok(models::ChallengeScores::new(
        scores_challenge_id,
        next_score,
        challenge_solves,
    ))
}

pub async fn get_challenge_scores_special1(
    conn: &mut PgConnection,
    scores_challenge_id: ChallengeId,
    scoring_parameters: &ScoringParameters,
) -> Result<models::ChallengeScores, DbError> {
    use crate::schema::exploits::dsl::*;
    use diesel::dsl::not;

    let solves = exploits
        .filter(
            challenge_id
                .eq(scores_challenge_id)
                .and(not(team_id.eq(23))) // TODO(P2): Replace this in the future with some flag on some team entity or something
                .and(status.eq(ExploitStatus::RunSolved)),
        )
        .order(submission_time.asc())
        .load::<Exploit>(conn)?;

    let score = scoring_parameters.max_score;

    let challenge_solves = solves
        .iter()
        .map(|exploit| {
            models::ChallengeSolve::new(
                *exploit.exploit_id(),
                *exploit.team_id(),
                *exploit.submission_time(),
                Some(score),
                exploit.score_awarded().is_some(),
            )
        })
        .collect();

    Ok(models::ChallengeScores::new(
        scores_challenge_id,
        score,
        challenge_solves,
    ))
}

pub fn get_object_store_url_prefix(
    storage_type: &str,
    exploits_path: &str,
) -> Result<String, object_store::Error> {
    match storage_type {
        "local" => Ok(exploits_path.to_string()),
        "aws" => Ok(format!("s3://{exploits_path}/")),
        "azure" => Ok(format!("az://{exploits_path}/")),
        "gcp" => Ok(format!("gs://{exploits_path}/")),
        _ => {
            log::error!(
                "ObjectStore of type {} not supported. Must be one of: local, aws, azure or gcp",
                storage_type
            );
            Err(object_store::Error::NotImplemented)
        }
    }
}

pub fn get_object_store(
    storage_type: &str,
    exploits_path: &str,
) -> object_store::Result<Arc<dyn ObjectStore>> {
    let store: Arc<dyn ObjectStore> = match storage_type {
        "local" => Arc::new(LocalFileSystem::new_with_prefix(exploits_path)?),
        "aws" => Arc::new(
            AmazonS3Builder::from_env()
                .with_bucket_name(exploits_path)
                .build()?,
        ),
        "azure" => Arc::new(
            MicrosoftAzureBuilder::from_env()
                .with_container_name(exploits_path)
                .build()?,
        ),
        "gcp" => Arc::new(
            GoogleCloudStorageBuilder::from_env()
                .with_bucket_name(exploits_path)
                .build()?,
        ),
        _ => {
            log::error!(
                "ObjectStore of type {} not supported. Must be one of: local, aws, azure or gcp",
                storage_type
            );
            return Err(object_store::Error::NotImplemented);
        }
    };

    Ok(store)
}

pub fn setup_database_pool(
    conn_spec: &str,
) -> Result<diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>, r2d2::Error> {
    // set up database connection pool
    let manager = diesel::r2d2::ConnectionManager::<PgConnection>::new(conn_spec);
    let pool = diesel::r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    let mut conn = match pool.get() {
        Ok(conn) => conn,
        Err(err) => return Err(err),
    };
    run_migration(&mut conn);
    Ok(pool)
}

pub const MIGRATIONS: diesel_migrations::EmbeddedMigrations =
    diesel_migrations::embed_migrations!();
fn run_migration(conn: &mut PgConnection) {
    conn.run_pending_migrations(MIGRATIONS)
        .expect("Failed to run migrations. Please investigate and try again.");
}

#[cfg(test)]
mod tests {

    // TODO (P2): tests?
}
