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
INSERT INTO policies VALUES(100,'wazuhPolicy','{"actions": ["*:*"], "resources": ["*:*"], "effect": "allow"}','2019-12-10 12:46:53.514184');
INSERT INTO policies VALUES(101,'wazuh-wuiPolicy','{"actions": ["agent:create"], "effect": "allow", "resources": ["agent:id:001", "agent:id:002", "agent:id:003"]}','2019-12-10 12:54:06.790926');
INSERT INTO policies VALUES(102,'technicalPolicy','{"actions": ["agent:create"], "effect": "allow", "resources": ["*:*:*"]}','2019-12-10 12:54:32.751662');
INSERT INTO policies VALUES(103,'administratorPolicy','{"actions": ["agent:update", "agent:delete"], "effect": "allow", "resources": ["agent:id:*"]}','2019-12-10 12:54:48.643254');
INSERT INTO policies VALUES(104,'normalPolicy','{"actions": ["agent:update", "agent:delete"], "effect": "deny", "resources": ["agent:id:*"]}','2019-12-10 12:55:03.620567');
INSERT INTO policies VALUES(105,'ossecPolicy','{"actions": ["role:read"], "effect": "allow", "resources": ["role:id:*"]}','2019-12-10 12:55:18.204798');
INSERT INTO policies VALUES(106,'policy1','{"actions": ["role:read"], "effect": "deny", "resources": ["role:id:*"]}','2019-12-10 12:56:52.704419');
INSERT INTO policies VALUES(107,'policy2','{"actions": ["role:read"], "effect": "allow", "resources": ["role:id:1"]}','2019-12-10 12:57:10.575688');
INSERT INTO policies VALUES(108,'policy3','{"actions": ["policy:read"], "effect": "allow", "resources": ["policy:id:1"]}','2019-12-10 12:57:26.105046');
INSERT INTO policies VALUES(109,'policy4','{"actions": ["policy:delete"], "effect": "deny", "resources": ["policy:id:*"]}','2019-12-10 12:57:40.203363');

/* Testing */
INSERT INTO roles_policies VALUES(100,8,100,0,'2019-12-10 12:46:53.227083');
INSERT INTO roles_policies VALUES(101,9,100,0,'2019-12-10 12:46:53.227083');
INSERT INTO roles_policies VALUES(102,10,101,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(103,10,100,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(104,10,107,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(105,10,104,3,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(106,11,104,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(107,11,103,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(108,12,101,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(109,12,102,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(110,12,109,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(111,13,101,0,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(112,13,107,1,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(113,13,106,2,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(114,13,109,3,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(115,13,104,4,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(116,13,108,5,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(117,13,100,6,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(118,13,105,7,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(119,13,102,100,'2019-12-10 12:47:07.032311');
INSERT INTO roles_policies VALUES(120,13,103,101,'2019-12-10 12:47:07.032311');

/* Testing */
INSERT INTO user_roles VALUES(109,'wazuh',8,1,'2020-03-25 10:22:38.704654');
INSERT INTO user_roles VALUES(110,'wazuh-wui',9,2,'2020-03-25 10:22:38.704654');
INSERT INTO user_roles VALUES(100,'administrator',9,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(101,'normal',12,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(102,'normal',13,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(103,'normal',11,2,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(104,'ossec',9,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(105,'ossec',12,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(106,'rbac',12,0,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(107,'rbac',10,1,'2019-12-10 12:47:07.035057');
INSERT INTO user_roles VALUES(108,'rbac',11,2,'2019-12-10 12:47:07.035057');
