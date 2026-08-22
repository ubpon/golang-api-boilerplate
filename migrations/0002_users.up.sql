CREATE TABLE users (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 citext      NOT NULL,
    display_email         text        NOT NULL,
    password_hash         text        NOT NULL,
    name                  text        NOT NULL DEFAULT '',
    email_verified_at     timestamptz,
    failed_login_attempts integer     NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_length CHECK (char_length(email::text) BETWEEN 3 AND 254),
    CONSTRAINT users_name_length CHECK (char_length(name) <= 200),
    CONSTRAINT users_failed_login_attempts_non_negative CHECK (failed_login_attempts >= 0)
);

CREATE UNIQUE INDEX users_email_key ON users (email);
CREATE INDEX users_locked_until_idx ON users (locked_until) WHERE locked_until IS NOT NULL;
