#ifndef LPOSIX_H
#define LPOSIX_H

#include <rpm/rpmutil.h>

RPM_GNUC_INTERNAL
void check_deprecated(lua_State *L, const char *func, const char *deprecated_in);

RPM_GNUC_INTERNAL
int luaopen_posix (lua_State *L);

#endif
