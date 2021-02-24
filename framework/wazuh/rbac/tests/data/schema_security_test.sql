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
INSERT INTO users VALUES(100,'administrator','pbkdf2:sha256:150000$QeB4uaGN$af22f78293952aaedad72b21efac557c9c32dea0a1e445080a6cb0f1c6259b62',0,'1970-01-01 00:00:00', 'user');
INSERT INTO users VALUES(101,'normal','pbkdf2:sha256:150000$LtJcBzd0$c768527541e515e9601571b9b9d3f5636b91d47dbe4341df83b8ad7ff51b7893',0,'1970-01-01 00:00:00', 'user');
INSERT INTO users VALUES(102,'ossec','pbkdf2:sha256:150000$TyLx9vsB$be2db27d007fa1d508791b6ccdab9151ed013f875fab444bd18d0d9f6b102380',0,'1970-01-01 00:00:00', 'user');
INSERT INTO users VALUES(103,'python','pbkdf2:sha256:150000$wO4Kq816$92dfe997f796e5d550a2641577d17ed5d1dc136bf64d5376629167159625a1ce',0,'1970-01-01 00:00:00', 'user');
INSERT INTO users VALUES(104,'rbac','pbkdf2:sha256:150000$eQAz1s4i$12c6ffdd7f290a12edf7ab1c7128ffac684abea78db2889494d4f9c8d0b92235',0,'1970-01-01 00:00:00', 'user');
INSERT INTO users VALUES(105,'guest','pbkdf2:sha256:150000$O9tFseJW$7659fc551aa6ed9cf207434d90d1da388f6840ce7bba5967a16949d4a94d1579',0,'1970-01-01 00:00:00', 'user');

/* Testing */
INSERT INTO roles VALUES(100,'wazuh','1970-01-01 00:00:00', 'user');
INSERT INTO roles VALUES(101,'wazuh-wui','1970-01-01 00:00:00', 'user');
INSERT INTO roles VALUES(102,'technical','1970-01-01 00:00:00', 'user');
INSERT INTO roles VALUES(103,'administrator_test','1970-01-01 00:00:00', 'user');
INSERT INTO roles VALUES(104,'normalUser','1970-01-01 00:00:00', 'user');
INSERT INTO roles VALUES(105,'ossec','1970-01-01 00:00:00', 'user');

/* Testing */
INSERT INTO rules VALUES(100,'rule1','{"FIND": {"r''^auth[a-zA-Z]+$''": ["administrator"]}}','1970-01-01 00:00:00', 'user');
INSERT INTO rules VALUES(101,'rule2','{"FIND": {"r''^auth[a-zA-Z]+$''": ["administrator-app"]}}','1970-01-01 00:00:00', 'user');
INSERT INTO rules VALUES(102,'rule3','{"MATCH": {"definition": "technicalRule"}}','1970-01-01 00:00:00', 'user');
INSERT INTO rules VALUES(103,'rule4','{"MATCH": {"definition": "administratorRule"}}','1970-01-01 00:00:00', 'user');
INSERT INTO rules VALUES(104,'rule5','{"MATCH": {"definition": "normalRule"}}','1970-01-01 00:00:00', 'user');
INSERT INTO rules VALUES(105,'rule6','{"MATCH": {"definition": "ossecRule"}}','1970-01-01 00:00:00', 'user');

/* Testing */
INSERT INTO policies VALUES(100,'wazuhPolicy','{"actions": ["*:*"], "resources": ["*:*"], "effect": "allow"}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(101,'wazuh-wuiPolicy','{"actions": ["agent:create"], "effect": "allow", "resources": ["agent:id:001", "agent:id:002", "agent:id:003"]}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(102,'technicalPolicy','{"actions": ["agent:create"], "effect": "allow", "resources": ["*:*:*"]}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(103,'administratorPolicy','{"actions": ["agent:update", "agent:delete"], "effect": "allow", "resources": ["agent:id:*"]}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(104,'normalPolicy','{"actions": ["agent:update", "agent:delete"], "effect": "deny", "resources": ["agent:id:*"]}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(105,'ossecPolicy','{"actions": ["role:read"], "effect": "allow", "resources": ["role:id:*"]}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(106,'policy1','{"actions": ["role:read"], "effect": "deny", "resources": ["role:id:*"]}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(107,'policy2','{"actions": ["role:read"], "effect": "allow", "resources": ["role:id:1"]}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(108,'policy3','{"actions": ["policy:read"], "effect": "allow", "resources": ["policy:id:1"]}','1970-01-01 00:00:00', 'user');
INSERT INTO policies VALUES(109,'policy4','{"actions": ["policy:delete"], "effect": "deny", "resources": ["policy:id:*"]}','1970-01-01 00:00:00', 'user');

/* Testing */
INSERT INTO roles_policies VALUES(100,100,100,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(101,101,100,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(102,102,101,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(103,102,100,1,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(104,102,107,2,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(105,102,104,3,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(106,103,104,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(107,103,103,1,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(108,104,101,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(109,104,102,1,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(110,104,109,2,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(111,105,101,0,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(112,105,107,1,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(113,105,106,2,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(114,105,109,3,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(115,105,104,4,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(116,105,108,5,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(117,105,100,6,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(118,105,105,7,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(119,105,102,8,'1970-01-01 00:00:00');
INSERT INTO roles_policies VALUES(120,105,103,9,'1970-01-01 00:00:00');

/* Testing */
INSERT INTO user_roles VALUES(100,100,100,0,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(101,103,101,0,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(102,100,101,1,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(103,101,104,0,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(104,101,105,1,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(105,101,103,2,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(106,102,101,0,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(107,102,104,1,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(108,104,104,0,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(109,104,102,1,'1970-01-01 00:00:00');
INSERT INTO user_roles VALUES(110,104,103,2,'1970-01-01 00:00:00');

INSERT INTO roles_rules VALUES(100,100,100,'1970-01-01 00:00:00');
INSERT INTO roles_rules VALUES(101,101,101,'1970-01-01 00:00:00');
INSERT INTO roles_rules VALUES(102,102,102,'1970-01-01 00:00:00');
INSERT INTO roles_rules VALUES(103,103,103,'1970-01-01 00:00:00');
INSERT INTO roles_rules VALUES(104,104,104,'1970-01-01 00:00:00');
INSERT INTO roles_rules VALUES(105,105,105,'1970-01-01 00:00:00');

COMMIT;
