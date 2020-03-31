/*
 * SQL Schema security tests
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE users (username VARCHAR(32) NOT NULL, password VARCHAR(256), auth_context BOOLEAN DEFAULT FALSE NOT NULL, created_at DATETIME, PRIMARY KEY (username));

CREATE TABLE roles (id INTEGER NOT NULL, name VARCHAR(20), rule TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_role UNIQUE (name), CONSTRAINT role_definition UNIQUE (rule));

CREATE TABLE policies (id INTEGER NOT NULL, name VARCHAR(20), policy TEXT, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT name_policy UNIQUE (name),	CONSTRAINT policy_definition UNIQUE (policy));

CREATE TABLE roles_policies (id INTEGER NOT NULL, role_id INTEGER, policy_id INTEGER, level INTEGER, created_at DATETIME, PRIMARY KEY (id), CONSTRAINT role_policy UNIQUE (role_id, policy_id), FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE, FOREIGN KEY(policy_id) REFERENCES policies (id) ON DELETE CASCADE);

CREATE TABLE user_roles (id INTEGER NOT NULL, user_id INTEGER, role_id INTEGER, level INTEGER,	created_at DATETIME, PRIMARY KEY (id), CONSTRAINT user_role UNIQUE (user_id, role_id), FOREIGN KEY(user_id) REFERENCES users (username) ON DELETE CASCADE, FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE);

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

/* Default users */
INSERT INTO users VALUES('wazuh','pbkdf2:sha256:150000$OMVAATei$cb30da77537eea26b964265dab6f403e9499f18522c7cc9e6ba2cb2d33694e1f',0,'2020-03-25 10:22:38.887642');
INSERT INTO users VALUES('wazuh-wui','pbkdf2:sha256:150000$wbPFpWBC$e3dee9520837bc0e49dd92c3ea4d59ecf7539a9314be2d5cc7582a9ff37d478f',1,'2020-03-25 10:22:38.984829');

/* Testing */
INSERT INTO users VALUES('administrator','pbkdf2:sha256:150000$QeB4uaGN$af22f78293952aaedad72b21efac557c9c32dea0a1e445080a6cb0f1c6259b62',0,'2019-12-10 12:48:06.926632');
INSERT INTO users VALUES('normal','pbkdf2:sha256:150000$LtJcBzd0$c768527541e515e9601571b9b9d3f5636b91d47dbe4341df83b8ad7ff51b7893',0,'2019-12-10 12:48:14.331597');
INSERT INTO users VALUES('ossec','pbkdf2:sha256:150000$TyLx9vsB$be2db27d007fa1d508791b6ccdab9151ed013f875fab444bd18d0d9f6b102380',0,'2019-12-10 12:48:21.053495');
INSERT INTO users VALUES('python','pbkdf2:sha256:150000$wO4Kq816$92dfe997f796e5d550a2641577d17ed5d1dc136bf64d5376629167159625a1ce',0,'2019-12-10 12:48:26.038905');
INSERT INTO users VALUES('rbac','pbkdf2:sha256:150000$eQAz1s4i$12c6ffdd7f290a12edf7ab1c7128ffac684abea78db2889494d4f9c8d0b92235',0,'2019-12-10 12:48:32.701316');
INSERT INTO users VALUES('guest','pbkdf2:sha256:150000$O9tFseJW$7659fc551aa6ed9cf207434d90d1da388f6840ce7bba5967a16949d4a94d1579',0,'2019-12-10 12:48:37.632985');

/* Default roles */
INSERT INTO roles VALUES(1,'administrator','{"FIND": {"r''^auth[a-zA-Z]+$''": ["full_admin"]}}','2020-03-25 10:22:39.009933');
INSERT INTO roles VALUES(2,'readonly','{"FIND": {"r''^auth[a-zA-Z]+$''": ["readonly"]}}','2020-03-25 10:22:39.022155');
INSERT INTO roles VALUES(3,'users_admin','{"FIND": {"r''^auth[a-zA-Z]+$''": ["users_admin"]}}','2020-03-25 10:22:39.033925');
INSERT INTO roles VALUES(4,'agents_readonly','{"FIND": {"r''^auth[a-zA-Z]+$''": ["agents_readonly"]}}','2020-03-25 10:22:39.045610');
INSERT INTO roles VALUES(5,'agents_admin','{"FIND": {"r''^auth[a-zA-Z]+$''": ["agents_admin"]}}','2020-03-25 10:22:39.055289');
INSERT INTO roles VALUES(6,'cluster_readonly','{"FIND": {"r''^auth[a-zA-Z]+$''": ["cluster_readonly"]}}','2020-03-25 10:22:39.068829');
INSERT INTO roles VALUES(7,'cluster_admin','{"FIND": {"r''^auth[a-zA-Z]+$''": ["cluster_admin"]}}','2020-03-25 10:22:39.085211');

/* Testing */
INSERT INTO roles VALUES(8,'wazuh','{"FIND": {"r''^auth[a-zA-Z]+$''": ["administrator"]}}','2019-12-10 12:46:53.525980');
INSERT INTO roles VALUES(9,'wazuh-wui','{"FIND": {"r''^auth[a-zA-Z]+$''": ["administrator-app"]}}','2019-12-10 12:46:53.538116');
INSERT INTO roles VALUES(10,'technical','{"MATCH": {"definition": "technicalRule"}}','2019-12-10 12:49:33.274646');
INSERT INTO roles VALUES(11,'administrator_test','{"MATCH": {"definition": "administratorRule"}}','2019-12-10 12:49:53.307632');
INSERT INTO roles VALUES(12,'normalUser','{"MATCH": {"definition": "normalRule"}}','2019-12-10 12:50:10.472462');
INSERT INTO roles VALUES(13,'ossec','{"MATCH": {"definition": "ossecRule"}}','2019-12-10 12:50:25.378200');

/* Default policies */
INSERT INTO policies VALUES(1,'agents_all','{"actions": ["agent:read", "agent:create", "agent:delete", "agent:modify_group", "agent:restart", "agent:upgrade", "group:read", "group:delete", "group:create", "group:update_config", "group:modify_assignments"], "resources": ["agent:id:*", "group:id:*"], "effect": "allow"}','2020-03-25 10:22:39.124020');
INSERT INTO policies VALUES(2,'agents_read','{"actions": ["agent:read", "group:read"], "resources": ["agent:id:*", "group:id:*"], "effect": "allow"}','2020-03-25 10:22:39.136240');
INSERT INTO policies VALUES(3,'agents_commands','{"actions": ["active_response:send_command"], "resources": ["agent:id:*"], "effect": "allow"}','2020-03-25 10:22:39.147970');
INSERT INTO policies VALUES(4,'security_all','{"actions": ["security:read", "security:create", "security:update", "security:delete"], "resources": ["role:id:*", "policy:id:*", "user:id:*"], "effect": "allow"}','2020-03-25 10:22:39.162812');
INSERT INTO policies VALUES(5,'users_all','{"actions": ["security:read", "security:create", "security:update", "security:delete"], "resources": ["user:id:*"], "effect": "allow"}','2020-03-25 10:22:39.180296');
INSERT INTO policies VALUES(6,'ciscat_read','{"actions": ["ciscat:read"], "resources": ["agent:id:*"], "effect": "allow"}','2020-03-25 10:22:39.194307');
INSERT INTO policies VALUES(7,'decoders_read','{"actions": ["decoders:read"], "resources": ["decoder:file:*"], "effect": "allow"}','2020-03-25 10:22:39.208778');
INSERT INTO policies VALUES(8,'rules_read','{"actions": ["rules:read"], "resources": ["rules:file:*"], "effect": "allow"}','2020-03-25 10:22:39.223488');
INSERT INTO policies VALUES(9,'cluster_all','{"actions": ["cluster:read_config", "cluster:restart", "cluster:status", "cluster:read_file", "cluster:upload_file", "cluster:delete_file", "manager:read_config", "manager:delete_file", "manager:read_file", "manager:upload_file", "manager:restart"], "resources": ["file:path:*", "node:id:*", "node:id:*&file:path:*"], "effect": "allow"}','2020-03-25 10:22:39.238445');
INSERT INTO policies VALUES(10,'cluster_read','{"actions": ["cluster:read_config", "cluster:status", "cluster:read_file", "manager:read_config", "manager:read_file"], "resources": ["file:path:*", "node:id:*", "node:id:*&file:path:*"], "effect": "allow"}','2020-03-25 10:22:39.254928');

/* Testing */
INSERT INTO policies VALUES(11,'wazuhPolicy','{"actions": ["*:*"], "resources": ["*:*"], "effect": "allow"}','2019-12-10 12:46:53.514184');
INSERT INTO policies VALUES(12,'wazuh-wuiPolicy','{"actions": ["agent:create"], "effect": "allow", "resources": ["agent:id:001", "agent:id:002", "agent:id:003"]}','2019-12-10 12:54:06.790926');
INSERT INTO policies VALUES(13,'technicalPolicy','{"actions": ["agent:create"], "effect": "allow", "resources": ["*:*:*"]}','2019-12-10 12:54:32.751662');
INSERT INTO policies VALUES(14,'administratorPolicy','{"actions": ["agent:update", "agent:delete"], "effect": "allow", "resources": ["agent:id:*"]}','2019-12-10 12:54:48.643254');
INSERT INTO policies VALUES(15,'normalPolicy','{"actions": ["agent:update", "agent:delete"], "effect": "deny", "resources": ["agent:id:*"]}','2019-12-10 12:55:03.620567');
INSERT INTO policies VALUES(16,'ossecPolicy','{"actions": ["role:read"], "effect": "allow", "resources": ["role:id:*"]}','2019-12-10 12:55:18.204798');
INSERT INTO policies VALUES(17,'policy1','{"actions": ["role:read"], "effect": "deny", "resources": ["role:id:*"]}','2019-12-10 12:56:52.704419');
INSERT INTO policies VALUES(18,'policy2','{"actions": ["role:read"], "effect": "allow", "resources": ["role:id:1"]}','2019-12-10 12:57:10.575688');
INSERT INTO policies VALUES(19,'policy3','{"actions": ["policy:read"], "effect": "allow", "resources": ["policy:id:1"]}','2019-12-10 12:57:26.105046');
INSERT INTO policies VALUES(20,'policy4','{"actions": ["policy:delete"], "effect": "deny", "resources": ["policy:id:*"]}','2019-12-10 12:57:40.203363');

/* Default roles-policies links */
INSERT INTO roles_policies VALUES(1,1,1,0,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(2,1,3,1,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(3,1,4,2,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(4,1,9,3,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(5,1,6,4,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(6,1,7,5,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(7,1,8,6,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(8,2,2,0,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(9,2,6,1,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(10,2,7,2,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(11,2,8,3,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(12,3,5,0,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(13,4,2,0,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(14,5,1,0,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(15,6,10,0,'2020-03-25 10:22:38.701536');
INSERT INTO roles_policies VALUES(16,7,9,1,'2020-03-25 10:22:38.701536');

/* Testing */
INSERT INTO roles_policies VALUES(17,8,11,0,'2019-12-10 12:46:53.227083');
INSERT INTO roles_policies VALUES(18,9,11,0,'2019-12-10 12:46:53.227083');
INSERT INTO roles_policies VALUES(19,10,12,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(20,10,11,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(21,10,18,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(22,10,15,3,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(23,11,15,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(24,11,14,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(25,12,12,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(26,12,13,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(27,12,20,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(28,13,12,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(29,13,18,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(30,13,17,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(31,13,20,3,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(32,13,15,4,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(33,13,19,5,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(34,13,11,6,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(35,13,16,7,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(36,13,13,8,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(37,13,14,9,'2019-12-10 12:47:07.032311');

/* Default user-roles links */
INSERT INTO user_roles VALUES(1,'wazuh',1,0,'2020-03-25 10:22:38.704654');
INSERT INTO user_roles VALUES(2,'wazuh-wui',2,0,'2020-03-25 10:22:38.704654');

/* Testing */
INSERT INTO user_roles VALUES(3,'wazuh',8,1,'2020-03-25 10:22:38.704654');
INSERT INTO user_roles VALUES(4,'wazuh-wui',9,1,'2020-03-25 10:22:38.704654');
INSERT INTO user_roles VALUES(5,'administrator',9,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(6,'normal',12,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(7,'normal',13,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(8,'normal',11,2,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(9,'ossec',9,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(10,'ossec',12,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(11,'rbac',12,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(12,'rbac',10,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(13,'rbac',11,2,'2019-12-10 12:47:07.035057');

COMMIT;
