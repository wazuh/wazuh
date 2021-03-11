#include "wdb_agents.h"
#include <stdio.h>
 #include <openssl/sha.h>
 #include <string.h>
 #include <stdlib.h>


int wdb_agents_insert_vuln_cve(wdb_t *wdb, const char* name, const char* version, const char* architecture, const char* cve) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_INSERT);
    if (stmt == NULL) {
        return OS_INVALID;
    }

        /////////////////////////
    int return_val;
    SHA_CTX shactx;
    unsigned char digest[SHA_DIGEST_LENGTH];
    int i=0,j=0;
    char* item_id_final= (char*) malloc (sizeof(char)*SHA_DIGEST_LENGTH*2+1);

    SHA1_Init(&shactx);
    SHA1_Update(&shactx, name, strlen(name));
    SHA1_Update(&shactx, version, strlen(version));
    SHA1_Update(&shactx, architecture, strlen(architecture));
    SHA1_Final(digest, &shactx);

    for (i=0; i<SHA_DIGEST_LENGTH; i++) {
        char * test = (char*) malloc (sizeof(char) * 3);
        snprintf (test, 3, "%02x",digest[i]);
        strcpy(item_id_final+j,test);
        j+=2;
        os_free(test);
    }
    ///////////////////////////

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, version, -1, NULL);
    sqlite3_bind_text(stmt, 3, architecture, -1, NULL);
    sqlite3_bind_text(stmt, 4, item_id_final, -1, NULL);
    sqlite3_bind_text(stmt, 5, "VALID", -1, NULL);
    sqlite3_bind_text(stmt, 6, cve, -1, NULL);



    return_val = wdb_exec_stmt_silent(stmt);
    os_free(item_id_final);
    return return_val;

}

int wdb_agents_clear_vuln_cve(wdb_t *wdb) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_CLEAR);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}
