/*
 * SQL Schema security tests
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE users (id INTEGER NOT NULL, username VARCHAR(32), password VARCHAR(256), allow_run_as BOOLEAN NOT NULL, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT username_restriction UNIQUE (username), CHECK (allow_run_as IN (0, 1)));

CREATE TABLE roles (id INTEGER NOT NULL, name VARCHAR(20), created_at DATETIME,	PRIMARY KEY (id), CONSTRAINT name_role UNIQUE (name));

CREATE TABLE rules (id INTEGER NOT NULL, name VARCHAR(20), rule TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT rule_name UNIQUE (name), CONSTRAINT rule_definition UNIQUE (rule));

CREATE TABLE policies (id INTEGER NOT NULL, name VARCHAR(20), policy TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_policy UNIQUE (name),	CONSTRAINT policy_definition UNIQUE (policy));

CREATE TABLE roles_policies (id INTEGER NOT NULL, role_id INTEGER, policy_id INTEGER, level INTEGER, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT role_policy UNIQUE (role_id, policy_id), FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE, FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE CASCADE);

CREATE TABLE user_roles (id INTEGER NOT NULL, user_id INTEGER, role_id INTEGER, level INTEGER,	created_at DATETIME, PRIMARY KEY (id), CONSTRAINT user_role UNIQUE (user_id, role_id), FOREIGN KEY(user_id) REFERENCES users (username) ON DELETE CASCADE, FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE);

CREATE TABLE roles_rules (id INTEGER NOT NULL, role_id INTEGER, rule_id INTEGER, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT role_rule UNIQUE (role_id, rule_id), FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE, FOREIGN KEY(rule_id) REFERENCES rules (id) ON DELETE CASCADE);
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

/* testing user */
INSERT INTO users VALUES(199,'testing_auth_context','pbkdf2:sha256:150000$OMVAATei$cb30da77537eea26b964265dab6f403e9499f18522c7cc9e6ba2cb2d33694e1f',1,'1970-01-01 00:00:00');

COMMIT;
