use redis::AsyncCommands;

fn get_rate_limit_bucket(team_id: common::models::TeamId, rate_limit: chrono::Duration) -> String {
    let bucket_ts = chrono::Utc::now().timestamp() / rate_limit.num_seconds();
    let bucket = format!("rate-limit:{team_id}:{bucket_ts}");

    bucket
}

fn expire_bucket<'a, T: redis::FromRedisValue>(
    redis_con: &'a mut redis::aio::Connection,
    bucket: &'a str,
    rate_limit: chrono::Duration,
) -> redis::RedisFuture<'a, T> {
    redis_con.expire(bucket, 2 * rate_limit.num_seconds())
}

pub async fn revert_rate_limit(
    redis_client: &redis::Client,
    team_id: common::models::TeamId,
    rate_limit: chrono::Duration,
) -> Result<bool, redis::RedisError> {
    let mut redis_con = redis_client.get_tokio_connection().await?;
    let bucket = get_rate_limit_bucket(team_id, rate_limit);

    // TODO (P2): In theory, if this call fails but still creates a key, it will lack expiry
    let num_submissions_bucket: i64 = redis_con.decr(&bucket, 1).await?;
    expire_bucket(&mut redis_con, &bucket, rate_limit).await?;

    Ok(num_submissions_bucket == 0)
}

pub async fn check_rate_limit(
    redis_client: &redis::Client,
    team_id: common::models::TeamId,
    rate_limit: chrono::Duration,
) -> Result<bool, redis::RedisError> {
    let mut redis_con = redis_client.get_tokio_connection().await?;
    let bucket = get_rate_limit_bucket(team_id, rate_limit);

    // TODO (P2): In theory, if this call fails but still creates a key, it will lack expiry
    let num_submissions_bucket: i64 = redis_con.incr(&bucket, 1).await?;
    expire_bucket(&mut redis_con, &bucket, rate_limit).await?;

    Ok(num_submissions_bucket == 1)
}
