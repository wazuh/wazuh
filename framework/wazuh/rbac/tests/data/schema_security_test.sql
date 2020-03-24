/*
 * SQL Schema security tests
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE users (username VARCHAR(32) NOT NULL, password VARCHAR(256), created_at DATETIME, auth_context BOOLEAN DEFAULT FALSE NOT NULL, PRIMARY KEY (username));

CREATE TABLE roles (id INTEGER NOT NULL, name VARCHAR(20), rule TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_role UNIQUE (name), CONSTRAINT role_definition UNIQUE (rule));

CREATE TABLE policies (id INTEGER NOT NULL, name VARCHAR(20), policy TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_policy UNIQUE (name),	CONSTRAINT policy_definition UNIQUE (policy));

CREATE TABLE roles_policies (id INTEGER NOT NULL, role_id INTEGER, policy_id INTEGER, level INTEGER, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT role_policy UNIQUE (role_id, policy_id), FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE, FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE CASCADE);

CREATE TABLE user_roles (id INTEGER NOT NULL, user_id INTEGER, role_id INTEGER, level INTEGER,	created_at DATETIME, PRIMARY KEY (id), CONSTRAINT user_role UNIQUE (user_id, role_id), FOREIGN KEY(user_id) REFERENCES users (username) ON DELETE CASCADE, FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE);

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
INSERT INTO users VALUES('wazuh-wui','pbkdf2:sha256:150000$AVtzUL7O$fc20226398538ed5b0afacbd240867bb1f119966b607a8da64a8cbb73475aa3d','2019-12-10 12:46:53.399839',1);
INSERT INTO users VALUES('wazuh','pbkdf2:sha256:150000$WUpIPX6H$8607ce55a5c11143f82e8db3b68d3ab6590db0c1e07291ef9962854471507b50','2019-12-10 12:46:53.499862',0);
INSERT INTO users VALUES('administrator','pbkdf2:sha256:150000$QeB4uaGN$af22f78293952aaedad72b21efac557c9c32dea0a1e445080a6cb0f1c6259b62','2019-12-10 12:48:06.926632',0);
INSERT INTO users VALUES('normal','pbkdf2:sha256:150000$LtJcBzd0$c768527541e515e9601571b9b9d3f5636b91d47dbe4341df83b8ad7ff51b7893','2019-12-10 12:48:14.331597',0);
INSERT INTO users VALUES('ossec','pbkdf2:sha256:150000$TyLx9vsB$be2db27d007fa1d508791b6ccdab9151ed013f875fab444bd18d0d9f6b102380','2019-12-10 12:48:21.053495',0);
INSERT INTO users VALUES('python','pbkdf2:sha256:150000$wO4Kq816$92dfe997f796e5d550a2641577d17ed5d1dc136bf64d5376629167159625a1ce','2019-12-10 12:48:26.038905',0);
INSERT INTO users VALUES('rbac','pbkdf2:sha256:150000$eQAz1s4i$12c6ffdd7f290a12edf7ab1c7128ffac684abea78db2889494d4f9c8d0b92235','2019-12-10 12:48:32.701316',0);
INSERT INTO users VALUES('guest','pbkdf2:sha256:150000$O9tFseJW$7659fc551aa6ed9cf207434d90d1da388f6840ce7bba5967a16949d4a94d1579','2019-12-10 12:48:37.632985',0);

INSERT INTO roles VALUES(1,'wazuh','{"FIND": {"r''^auth[a-zA-Z]+$''": ["administrator"]}}','2019-12-10 12:46:53.525980');
INSERT INTO roles VALUES(2,'wazuh-wui','{"FIND": {"r''^auth[a-zA-Z]+$''": ["administrator-app"]}}','2019-12-10 12:46:53.538116');
INSERT INTO roles VALUES(3,'technical','{"MATCH": {"definition": "technicalRule"}}','2019-12-10 12:49:33.274646');
INSERT INTO roles VALUES(4,'administrator','{"MATCH": {"definition": "administratorRule"}}','2019-12-10 12:49:53.307632');
INSERT INTO roles VALUES(5,'normalUser','{"MATCH": {"definition": "normalRule"}}','2019-12-10 12:50:10.472462');
INSERT INTO roles VALUES(6,'ossec','{"MATCH": {"definition": "ossecRule"}}','2019-12-10 12:50:25.378200');

INSERT INTO policies VALUES(1,'wazuhPolicy','{"actions": ["*:*"], "resources": ["*:*"], "effect": "allow"}','2019-12-10 12:46:53.514184');
INSERT INTO policies VALUES(2,'wazuh-wuiPolicy','{"actions": ["agent:create"], "effect": "allow", "resources": ["agent:id:001", "agent:id:002", "agent:id:003"]}','2019-12-10 12:54:06.790926');
INSERT INTO policies VALUES(3,'technicalPolicy','{"actions": ["agent:create"], "effect": "allow", "resources": ["*:*:*"]}','2019-12-10 12:54:32.751662');
INSERT INTO policies VALUES(4,'administratorPolicy','{"actions": ["agent:update", "agent:delete"], "effect": "allow", "resources": ["agent:id:*"]}','2019-12-10 12:54:48.643254');
INSERT INTO policies VALUES(5,'normalPolicy','{"actions": ["agent:update", "agent:delete"], "effect": "deny", "resources": ["agent:id:*"]}','2019-12-10 12:55:03.620567');
INSERT INTO policies VALUES(6,'ossecPolicy','{"actions": ["role:read"], "effect": "allow", "resources": ["role:id:*"]}','2019-12-10 12:55:18.204798');
INSERT INTO policies VALUES(7,'policy1','{"actions": ["role:read"], "effect": "deny", "resources": ["role:id:*"]}','2019-12-10 12:56:52.704419');
INSERT INTO policies VALUES(8,'policy2','{"actions": ["role:read"], "effect": "allow", "resources": ["role:id:1"]}','2019-12-10 12:57:10.575688');
INSERT INTO policies VALUES(9,'policy3','{"actions": ["policy:read"], "effect": "allow", "resources": ["policy:id:1"]}','2019-12-10 12:57:26.105046');
INSERT INTO policies VALUES(10,'policy4','{"actions": ["policy:delete"], "effect": "deny", "resources": ["policy:id:*"]}','2019-12-10 12:57:40.203363');

INSERT INTO roles_policies VALUES(1,1,1,0,'2019-12-10 12:46:53.227083');
INSERT INTO roles_policies VALUES(2,2,1,0,'2019-12-10 12:46:53.227083');
INSERT INTO roles_policies VALUES(3,3,2,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(4,3,1,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(5,3,8,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(6,3,5,3,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(7,4,5,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(8,4,4,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(9,5,2,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(10,5,3,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(11,5,10,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(12,6,2,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(13,6,8,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(14,6,7,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(15,6,10,3,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(16,6,5,4,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(17,6,9,5,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(18,6,1,6,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(19,6,6,7,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(20,6,3,8,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(21,6,4,9,'2019-12-10 12:47:07.032311');

INSERT INTO user_roles VALUES(1,'wazuh',1,0,'2019-12-10 12:46:53.229308');
INSERT INTO user_roles VALUES(2,'wazuh-app',1,0,'2019-12-10 12:46:53.229308');
INSERT INTO user_roles VALUES(3,'administrator',2,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(4,'normal',5,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(5,'normal',6,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(6,'normal',4,2,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(7,'ossec',2,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(8,'ossec',5,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(9,'rbac',5,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(10,'rbac',3,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(11,'rbac',4,2,'2019-12-10 12:47:07.035057');
