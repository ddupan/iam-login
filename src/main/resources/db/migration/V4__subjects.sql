-- OIDC subjects are issued by this server, not derived from a directory: a directory account is only linked to
-- one, so accounts outside AD and a later move off AD keep their subjects (and every RP's account link).
create table subjects
(
    subject      varchar(255) not null,
    authority    varchar(255) not null,
    directory_id varchar(255) not null,
    created      timestamptz  not null default now(),
    primary key (subject),
    unique (authority, directory_id)
);
