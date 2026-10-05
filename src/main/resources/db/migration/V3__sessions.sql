-- HTTP sessions in the database (Spring Session JDBC), so restarts and replicas keep logins.
-- Upstream schema-postgresql.sql of spring-session-jdbc 4.1.1, unchanged: the repository's SQL
-- relies on these names. Attribute values are JSON (see SessionConfiguration), not Java serialization.
CREATE TABLE SPRING_SESSION (
	PRIMARY_ID CHAR(36) NOT NULL,
	SESSION_ID CHAR(36) NOT NULL,
	CREATION_TIME BIGINT NOT NULL,
	LAST_ACCESS_TIME BIGINT NOT NULL,
	MAX_INACTIVE_INTERVAL INT NOT NULL,
	EXPIRY_TIME BIGINT NOT NULL,
	PRINCIPAL_NAME VARCHAR(100),
	CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (PRIMARY_ID)
);

CREATE UNIQUE INDEX SPRING_SESSION_IX1 ON SPRING_SESSION (SESSION_ID);
CREATE INDEX SPRING_SESSION_IX2 ON SPRING_SESSION (EXPIRY_TIME);
CREATE INDEX SPRING_SESSION_IX3 ON SPRING_SESSION (PRINCIPAL_NAME);

CREATE TABLE SPRING_SESSION_ATTRIBUTES (
	SESSION_PRIMARY_ID CHAR(36) NOT NULL,
	ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
	ATTRIBUTE_BYTES BYTEA NOT NULL,
	CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
	CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID) REFERENCES SPRING_SESSION(PRIMARY_ID) ON DELETE CASCADE
);

-- Pending WebAuthn ceremonies. Kept out of the session so that consuming one is a single
-- DELETE ... RETURNING: with the session in the database, concurrent requests each load their own
-- copy, and only the database can make a challenge single-use. The session holds only the id.
CREATE TABLE webauthn_challenge (
	id uuid PRIMARY KEY,
	purpose text NOT NULL,
	owner text NOT NULL,
	options bytea NOT NULL,
	expires_at timestamptz NOT NULL
);
CREATE INDEX webauthn_challenge_expires_at ON webauthn_challenge (expires_at);
