/*
 * SQL Schema security tests
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

/* Testing */
INSERT INTO users VALUES('administrator','pbkdf2:sha256:150000$QeB4uaGN$af22f78293952aaedad72b21efac557c9c32dea0a1e445080a6cb0f1c6259b62',0,'2019-12-10 12:48:06.926632');
INSERT INTO users VALUES('normal','pbkdf2:sha256:150000$LtJcBzd0$c768527541e515e9601571b9b9d3f5636b91d47dbe4341df83b8ad7ff51b7893',0,'2019-12-10 12:48:14.331597');
INSERT INTO users VALUES('ossec','pbkdf2:sha256:150000$TyLx9vsB$be2db27d007fa1d508791b6ccdab9151ed013f875fab444bd18d0d9f6b102380',0,'2019-12-10 12:48:21.053495');
INSERT INTO users VALUES('python','pbkdf2:sha256:150000$wO4Kq816$92dfe997f796e5d550a2641577d17ed5d1dc136bf64d5376629167159625a1ce',0,'2019-12-10 12:48:26.038905');
INSERT INTO users VALUES('rbac','pbkdf2:sha256:150000$eQAz1s4i$12c6ffdd7f290a12edf7ab1c7128ffac684abea78db2889494d4f9c8d0b92235',0,'2019-12-10 12:48:32.701316');
INSERT INTO users VALUES('guest','pbkdf2:sha256:150000$O9tFseJW$7659fc551aa6ed9cf207434d90d1da388f6840ce7bba5967a16949d4a94d1579',0,'2019-12-10 12:48:37.632985');

/* Testing */
INSERT INTO roles VALUES(8,'wazuh','{"FIND": {"r''^auth[a-zA-Z]+$''": ["administrator"]}}','2019-12-10 12:46:53.525980');
INSERT INTO roles VALUES(9,'wazuh-wui','{"FIND": {"r''^auth[a-zA-Z]+$''": ["administrator-app"]}}','2019-12-10 12:46:53.538116');
INSERT INTO roles VALUES(10,'technical','{"MATCH": {"definition": "technicalRule"}}','2019-12-10 12:49:33.274646');
INSERT INTO roles VALUES(11,'administrator_test','{"MATCH": {"definition": "administratorRule"}}','2019-12-10 12:49:53.307632');
INSERT INTO roles VALUES(12,'normalUser','{"MATCH": {"definition": "normalRule"}}','2019-12-10 12:50:10.472462');
INSERT INTO roles VALUES(13,'ossec','{"MATCH": {"definition": "ossecRule"}}','2019-12-10 12:50:25.378200');

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

/* Testing */
INSERT INTO user_roles VALUES(5,'administrator',9,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(6,'normal',12,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(7,'normal',13,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(8,'normal',11,2,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(9,'ossec',9,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(10,'ossec',12,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(11,'rbac',12,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(12,'rbac',10,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(13,'rbac',11,2,'2019-12-10 12:47:07.035057');
