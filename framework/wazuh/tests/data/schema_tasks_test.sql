PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

CREATE TABLE TASKS (
                    TASK_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    AGENT_ID INT NOT NULL,
                    NODE TEXT NOT NULL,
                    MODULE TEXT NOT NULL,
                    COMMAND TEXT NOT NULL,
                    CREATE_TIME INTEGER NOT NULL,
                    LAST_UPDATE_TIME INTEGER,
                    STATUS TEXT NOT NULL,
                    ERROR_MESSAGE TEXT DEFAULT NULL
                   );

CREATE TABLE METADATA (
                       key TEXT PRIMARY KEY,
                       value TEXT
                      );

INSERT INTO TASKS VALUES(1,2,'worker2','upgrade_module','upgrade',1606466932,1606466953,'Legacy',NULL);
INSERT INTO TASKS VALUES(2,3,'master-node','upgrade_module','upgrade',1606466983,1606466983,'Failed','The version of the WPK does not exist in the repository');
INSERT INTO TASKS VALUES(3,1,'worker2','upgrade_module','upgrade',1606466989,1606467007,'Legacy',NULL);
INSERT INTO TASKS VALUES(4,2,'worker2','upgrade_module','upgrade',1606466998,1606467017,'Legacy',NULL);
INSERT INTO TASKS VALUES(5,2,'worker2','upgrade_module','upgrade',1606467074,1606467074,'Failed','The version of the WPK does not exist in the repository');
INSERT INTO TASKS VALUES(6,2,'worker2','upgrade_module','upgrade',1606467097,1606467114,'Legacy',NULL);

INSERT INTO METADATA VALUES('db_version','1');
