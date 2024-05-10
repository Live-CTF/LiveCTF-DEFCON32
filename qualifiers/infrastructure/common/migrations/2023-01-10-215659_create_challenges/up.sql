CREATE TYPE scoring_model AS ENUM ('normal', 'unscored', 'special1');

CREATE TABLE challenges (
    challenge_id INTEGER PRIMARY KEY,
    challenge_short_name VARCHAR(256) NOT NULL,
    challenge_name VARCHAR(256) NOT NULL,
    uses_nsjail BOOLEAN NOT NULL,
    scoring_model scoring_model NOT NULL,
    releases_at TIMESTAMP NOT NULL,
    closes_at  TIMESTAMP NOT NULL
);
