-- At most one authenticator app per account (setting up again replaces it). owner is the principal name, as in
-- user_entities.name. The key is AES-GCM encrypted with iam.totp.key: a database dump alone cannot produce codes.
-- last_step is the newest 30-second step a code was accepted for; a code for it or an earlier step is a replay.
create table totp_credentials
(
    owner     varchar(100) not null,
    secret    bytea        not null,
    created   timestamptz  not null default now(),
    last_used timestamptz,
    last_step bigint       not null,
    primary key (owner)
);
