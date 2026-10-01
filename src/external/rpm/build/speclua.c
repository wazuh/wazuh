
#include "system.h"

#include "rpmlua.h"
#include "rpmbuild_internal.h"

#include "debug.h"

static const char * luavars[] = { "patches", "sources",
			       "patch_nums", "source_nums", NULL, };

void * specLuaInit(rpmSpec spec)
{
    rpmlua lua = rpmluaGetGlobalState();
    lua_State *L = (lua_State *)rpmluaGetLua(lua);
    for (const char **vp = luavars; vp && *vp; vp++) {
	lua_newtable(L);
	lua_setglobal(L, *vp);
    }

    return lua;
}

void * specLuaFini(rpmSpec spec)
{
    rpmlua lua = rpmluaGetGlobalState();
    lua_State *L = (lua_State *)rpmluaGetLua(lua);
    for (const char **vp = luavars; vp && *vp; vp++) {
	lua_pushnil(L);
	lua_setglobal(L, *vp);
    }
    return NULL;
}

void addLuaSource(const struct Source *p)
{
    rpmlua lua = rpmluaGetGlobalState();
    lua_State *L = (lua_State *)rpmluaGetLua(lua);
    const char * what = (p->flags & RPMBUILD_ISPATCH) ? "patches" : "sources";

    lua_getglobal(L, what);
    lua_pushstring(L, p->path);
    lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
    lua_pop(L, 1);

    what = (p->flags & RPMBUILD_ISPATCH) ? "patch_nums" : "source_nums";
    lua_getglobal(L, what);
    lua_pushinteger(L, p->num);
    lua_rawseti(L, -2, lua_rawlen(L, -2) + 1);
    lua_pop(L, 1);
}

