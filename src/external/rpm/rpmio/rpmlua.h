#ifndef RPMLUA_H
#define RPMLUA_H

#include <rpm/argv.h>

typedef struct rpmlua_s * rpmlua;
struct rpmhookArgs_s;

#ifdef __cplusplus
extern "C" {
#endif

/* Upstream Lua headers lack C++ protection, include them all centrally */
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#ifdef __cplusplus
}
#endif

typedef char * (*rpmluarl)(const char *);

rpmlua rpmluaNew(void);
rpmlua rpmluaFree(rpmlua lua);
rpmlua rpmluaGetGlobalState(void);
void *rpmluaGetLua(rpmlua lua);

int rpmluaCheckScript(rpmlua lua, const char *script,
		      const char *name);
int rpmluaRunScript(rpmlua lua, const char *script,
		    const char *name, const char *opts, ARGV_t args);
int rpmluaRunScriptFile(rpmlua lua, const char *filename);
void rpmluaInteractive(rpmlua lua, rpmluarl rlcb);

char *rpmluaPopPrintBuffer(rpmlua lua);
void rpmluaPushPrintBuffer(rpmlua lua);

char *rpmluaCallStringFunction(rpmlua lua, const char *function, struct rpmhookArgs_s *args);

#endif /* RPMLUA_H */
