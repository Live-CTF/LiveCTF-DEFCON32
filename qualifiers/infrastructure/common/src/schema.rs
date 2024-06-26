// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "exploit_status"))]
    pub struct ExploitStatus;

    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "scoring_model"))]
    pub struct ScoringModel;
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ScoringModel;

    challenges (challenge_id) {
        challenge_id -> Int4,
        #[max_length = 256]
        challenge_short_name -> Varchar,
        #[max_length = 256]
        challenge_name -> Varchar,
        uses_nsjail -> Bool,
        scoring_model -> ScoringModel,
        releases_at -> Timestamp,
        closes_at -> Timestamp,
    }
}

diesel::table! {
    exploit_outputs (output_id) {
        output_id -> Uuid,
        exploit_id -> Uuid,
        stdout -> Text,
        stderr -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ExploitStatus;

    exploits (exploit_id) {
        exploit_id -> Uuid,
        team_id -> Int4,
        team_token -> Text,
        challenge_id -> Int4,
        archive_id -> Uuid,
        pending -> Nullable<Bool>,
        status -> ExploitStatus,
        score_awarded -> Nullable<Int4>,
        submission_time -> Timestamp,
        run_duration -> Nullable<Int4>,
    }
}

diesel::joinable!(exploit_outputs -> exploits (exploit_id));
diesel::joinable!(exploits -> challenges (challenge_id));

diesel::allow_tables_to_appear_in_same_query!(challenges, exploit_outputs, exploits,);
