
OSSEC_GROUP?=ossec
PREFIX?=/var/ossec

hellomake: database/sqlite3.c
	gcc -pipe -O2 -shared -fPIC -o database/libsqlite3.so.0 database/sqlite3.c

	install -d -m 0750 -o root -g ${OSSEC_GROUP} ${PREFIX}/framework
	install -d -m 0750 -o root -g ${OSSEC_GROUP} ${PREFIX}/framework/examples
	install -d -m 0750 -o root -g ${OSSEC_GROUP} ${PREFIX}/framework/wazuh
	install -d -m 0750 -o root -g ${OSSEC_GROUP} ${PREFIX}/framework/lib

	install -m 750 -o root -g ${OSSEC_GROUP} examples/*.py ${PREFIX}/framework/examples
	install -m 750 -o root -g ${OSSEC_GROUP} wazuh/*.py ${PREFIX}/framework/wazuh
	install -m 640 -o root -g ${OSSEC_GROUP} database/libsqlite3.so.0 ${PREFIX}/framework/lib

	install -m 750 -o root -g root scripts/*.py ${PREFIX}/bin
