/*
* lposix.c
* POSIX library for Lua 5.0. Based on original by Claudio Terra for Lua 3.x.
* Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
* 05 Nov 2003 22:09:10
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <rpm/rpmutil.h>
#include "rpmio_internal.h"
#include "rpmlua.h"

#define MYNAME		"posix"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Nov 2003"

#include "lposix.h"

#ifndef MYBUFSIZ
#define MYBUFSIZ 512
#endif

#include "modemuncher.c"

extern int _rpmlua_have_forked;

static const char *filetype(mode_t m)
{
	if (S_ISREG(m))		return "regular";
	else if (S_ISLNK(m))	return "link";
	else if (S_ISDIR(m))	return "directory";
	else if (S_ISCHR(m))	return "character device";
	else if (S_ISBLK(m))	return "block device";
	else if (S_ISFIFO(m))	return "fifo";
	else if (S_ISSOCK(m))	return "socket";
	else			return "?";
}

typedef int (*Selector)(lua_State *L, int i, const void *data);

/* implemented as luaL_typerror until lua 5.1, dropped in 5.2
 * (C) 1994-2012 Lua.org, PUC-Rio. MIT license
 */
static int typerror (lua_State *L, int narg, const char *tname) {
	const char *msg = lua_pushfstring(L, "%s expected, got %s",
					  tname, luaL_typename(L, narg));
	return luaL_argerror(L, narg, msg);
}

static int doselection(lua_State *L, int i, const char *const S[], Selector F, const void *data)
{
	if (lua_isnone(L, i))
	{
		lua_newtable(L);
		for (i=0; S[i]!=NULL; i++)
		{
			lua_pushstring(L, S[i]);
			F(L, i, data);
			lua_settable(L, -3);
		}
		return 1;
	}
	else
	{
		int j=luaL_checkoption(L, i, NULL, S);
		if (j==-1) luaL_argerror(L, i, "unknown selector");
		return F(L, j, data);
	}
}

static void storeindex(lua_State *L, int i, const char *value)
{
	lua_pushstring(L, value);
	lua_rawseti(L, -2, i);
}

static void storestring(lua_State *L, const char *name, const char *value)
{
	lua_pushstring(L, name);
	lua_pushstring(L, value);
	lua_settable(L, -3);
}

static void storenumber(lua_State *L, const char *name, lua_Number value)
{
	lua_pushstring(L, name);
	lua_pushnumber(L, value);
	lua_settable(L, -3);
}

static int pusherror(lua_State *L, const char *info)
{
	lua_pushnil(L);
	if (info==NULL)
		lua_pushstring(L, strerror(errno));
	else
		lua_pushfstring(L, "%s: %s", info, strerror(errno));
	lua_pushnumber(L, errno);
	return 3;
}

static int pushresult(lua_State *L, int i, const char *info)
{
	if (i != -1)
	{
		lua_pushnumber(L, i);
		return 1;
	}
	else
		return pusherror(L, info);
}

static void badoption(lua_State *L, int i, const char *what, int option)
{
	luaL_argerror(L, 2,
		lua_pushfstring(L, "unknown %s option `%c'", what, option));
}

static uid_t mygetuid(lua_State *L, int i)
{
	if (lua_isnone(L, i))
		return -1;
	else if (lua_isnumber(L, i))
		return (uid_t) lua_tonumber(L, i);
	else if (lua_isstring(L, i))
	{
		struct passwd *p=getpwnam(lua_tostring(L, i));
		return (p==NULL) ? -1 : p->pw_uid;
	}
	else
		return typerror(L, i, "string or number");
}

static gid_t mygetgid(lua_State *L, int i)
{
	if (lua_isnone(L, i))
		return -1;
	else if (lua_isnumber(L, i))
		return (gid_t) lua_tonumber(L, i);
	else if (lua_isstring(L, i))
	{
		struct group *g=getgrnam(lua_tostring(L, i));
		return (g==NULL) ? -1 : g->gr_gid;
	}
	else
		return typerror(L, i, "string or number");
}



static int Perrno(lua_State *L)			/** errno() */
{
	lua_pushstring(L, strerror(errno));
	lua_pushnumber(L, errno);
	return 2;
}


static int Pdir(lua_State *L)			/** dir([path]) */
{
	const char *path = luaL_optstring(L, 1, ".");
	DIR *d = opendir(path);
	if (d == NULL)
		return pusherror(L, path);
	else
	{
		int i;
		struct dirent *entry;
		lua_newtable(L);
		for (i=1; (entry = readdir(d)) != NULL; i++)
			storeindex(L, i, entry->d_name);
		closedir(d);
		return 1;
	}
}


static int aux_files(lua_State *L)
{
	DIR *d = (DIR *)lua_touserdata(L, lua_upvalueindex(1));
	struct dirent *entry;
	if (d == NULL) return luaL_error(L, "attempt to use closed dir");
	entry = readdir(d);
	if (entry == NULL)
	{
		closedir(d);
		lua_pushnil(L);
		lua_replace(L, lua_upvalueindex(1));
		lua_pushnil(L);
	}
	else
	{
		lua_pushstring(L, entry->d_name);
#if 0
#ifdef _DIRENT_HAVE_D_TYPE
		lua_pushstring(L, filetype(DTTOIF(entry->d_type)));
		return 2;
#endif
#endif
	}
	return 1;
}

static int Pfiles(lua_State *L)			/** files([path]) */
{
	const char *path = luaL_optstring(L, 1, ".");
	DIR *d = opendir(path);
	if (d == NULL)
		return pusherror(L, path);
	else
	{
		lua_pushlightuserdata(L, d);
		lua_pushcclosure(L, aux_files, 1);
		return 1;
	}
}


static int Pgetcwd(lua_State *L)		/** getcwd() */
{
	char buf[MYBUFSIZ];
	if (getcwd(buf, sizeof(buf)) == NULL)
		return pusherror(L, ".");
	else
	{
		lua_pushstring(L, buf);
		return 1;
	}
}


static int Pmkdir(lua_State *L)			/** mkdir(path) */
{
	const char *path = luaL_checkstring(L, 1);
	return pushresult(L, mkdir(path, 0777), path);
}


static int Pchdir(lua_State *L)			/** chdir(path) */
{
	const char *path = luaL_checkstring(L, 1);
	return pushresult(L, chdir(path), path);
}


static int Prmdir(lua_State *L)			/** rmdir(path) */
{
	const char *path = luaL_checkstring(L, 1);
	return pushresult(L, rmdir(path), path);
}


static int Punlink(lua_State *L)		/** unlink(path) */
{
	const char *path = luaL_checkstring(L, 1);
	return pushresult(L, unlink(path), path);
}


static int Plink(lua_State *L)			/** link(oldpath,newpath) */
{
	const char *oldpath = luaL_checkstring(L, 1);
	const char *newpath = luaL_checkstring(L, 2);
	return pushresult(L, link(oldpath, newpath), NULL);
}


static int Psymlink(lua_State *L)		/** symlink(oldpath,newpath) */
{
	const char *oldpath = luaL_checkstring(L, 1);
	const char *newpath = luaL_checkstring(L, 2);
	return pushresult(L, symlink(oldpath, newpath), NULL);
}


static int Preadlink(lua_State *L)		/** readlink(path) */
{
	char buf[MYBUFSIZ];
	const char *path = luaL_checkstring(L, 1);
	int n = readlink(path, buf, sizeof(buf));
	if (n==-1) return pusherror(L, path);
	lua_pushlstring(L, buf, n);
	return 1;
}


static int Paccess(lua_State *L)		/** access(path,[mode]) */
{
	int mode=F_OK;
	const char *path=luaL_checkstring(L, 1);
	const char *s;
	for (s=luaL_optstring(L, 2, "f"); *s!=0 ; s++)
		switch (*s)
		{
			case ' ': break;
			case 'r': mode |= R_OK; break;
			case 'w': mode |= W_OK; break;
			case 'x': mode |= X_OK; break;
			case 'f': mode |= F_OK; break;
			default: badoption(L, 2, "mode", *s); break;
		}
	return pushresult(L, access(path, mode), path);
}


static int Pmkfifo(lua_State *L)		/** mkfifo(path) */
{
	const char *path = luaL_checkstring(L, 1);
	return pushresult(L, mkfifo(path, 0777), path);
}


static int Pexec(lua_State *L)			/** exec(path,[args]) */
{
	check_deprecated(L, "posix.exec", "4.20.0");

	const char *path = luaL_checkstring(L, 1);
	int i,n=lua_gettop(L);
	char **argv;

	if (!_rpmlua_have_forked)
	    return luaL_error(L, "exec not permitted in this context");

	rpmSetCloseOnExec();

	argv = (char **)malloc((n+1)*sizeof(char*));
	if (argv==NULL) return luaL_error(L,"not enough memory");
	argv[0] = (char*)path;
	for (i=1; i<n; i++) argv[i] = (char*)luaL_checkstring(L, i+1);
	argv[i] = NULL;
	execvp(path,argv);
	free(argv);
	return pusherror(L, path);
}


static int Pfork(lua_State *L)			/** fork() */
{
	check_deprecated(L, "posix.fork", "4.20.0");

	pid_t pid = fork();
	if (pid == 0) {
	    _rpmlua_have_forked = 1;
	}
	return pushresult(L, pid, NULL);
}


static int Pwait(lua_State *L)			/** wait([pid]) */
{
	check_deprecated(L, "posix.wait", "4.20.0");

	pid_t pid = luaL_optinteger(L, 1, -1);
	return pushresult(L, waitpid(pid, NULL, 0), NULL);
}


static int Pkill(lua_State *L)			/** kill(pid,[sig]) */
{
	pid_t pid = luaL_checkinteger(L, 1);
	int sig = luaL_optinteger(L, 2, SIGTERM);
	return pushresult(L, kill(pid, sig), NULL);
}


static int Psleep(lua_State *L)			/** sleep(seconds) */
{
	unsigned int seconds = luaL_checkinteger(L, 1);
	lua_pushnumber(L, sleep(seconds));
	return 1;
}


static int Pputenv(lua_State *L)		/** putenv(string) */
{
#ifdef HAVE_PUTENV
	size_t l;
	const char *s=luaL_checklstring(L, 1, &l);
	char *e=(char *)malloc(++l);
	return pushresult(L, (e==NULL) ? -1 : putenv((char *)memcpy(e,s,l)), s);
#else
	return -1;
#endif
}


static int Psetenv(lua_State *L)		/** setenv(name,value,[over]) */
{
	const char *name=luaL_checkstring(L, 1);
	const char *value=luaL_checkstring(L, 2);
	int overwrite=lua_isnoneornil(L, 3) || lua_toboolean(L, 3);
	return pushresult(L, setenv(name,value,overwrite), name);
}


static int Punsetenv(lua_State *L)		/** unsetenv(name) */
{
	const char *name=luaL_checkstring(L, 1);
	unsetenv(name);
	return 0;
}

static int Pgetenv(lua_State *L)		/** getenv([name]) */
{
	if (lua_isnone(L, 1))
	{
	#ifdef __APPLE__
		#include <crt_externs.h>
		#define environ (*_NSGetEnviron())
	#else
		extern char **environ;
	#endif /* __APPLE__ */
		char **e;
		if (*environ==NULL) lua_pushnil(L); else lua_newtable(L);
		for (e=environ; *e!=NULL; e++)
		{
			char *s=*e;
			char *eq=strchr(s, '=');
			if (eq==NULL)		/* will this ever happen? */
			{
				lua_pushstring(L,s);
				lua_pushboolean(L,0);
			}
			else
			{
				lua_pushlstring(L,s,eq-s);
				lua_pushstring(L,eq+1);
			}
			lua_settable(L,-3);
		}
	}
	else
		lua_pushstring(L, getenv(luaL_checkstring(L, 1)));
	return 1;
}


static int Pumask(lua_State *L)			/** umask([mode]) */
{
	char m[10];
	mode_t mode;
	umask(mode=umask(0));
	mode=(~mode)&0777;
	if (!lua_isnone(L, 1))
	{
		if (mode_munch(&mode, luaL_checkstring(L, 1)))
		{
			lua_pushnil(L);
			return 1;
		}
		mode&=0777;
		umask(~mode);
	}
	modechopper(mode, m);
	lua_pushstring(L, m);
	return 1;
}


static int Pchmod(lua_State *L)			/** chmod(path,mode) */
{
	mode_t mode;
	struct stat s;
	const char *path = luaL_checkstring(L, 1);
	const char *modestr = luaL_checkstring(L, 2);
	if (stat(path, &s)) return pusherror(L, path);
	mode = s.st_mode;
	if (mode_munch(&mode, modestr)) luaL_argerror(L, 2, "bad mode");
	return pushresult(L, chmod(path, mode), path);
}


static int Pchown(lua_State *L)			/** chown(path,uid,gid) */
{
	const char *path = luaL_checkstring(L, 1);
	uid_t uid = mygetuid(L, 2);
	gid_t gid = mygetgid(L, 3);
	return pushresult(L, chown(path, uid, gid), path);
}


static int Putime(lua_State *L)			/** utime(path,[mtime,atime]) */
{
	struct utimbuf times;
	time_t currtime = time(NULL);
	const char *path = luaL_checkstring(L, 1);
	times.modtime = luaL_optnumber(L, 2, currtime);
	times.actime  = luaL_optnumber(L, 3, currtime);
	return pushresult(L, utime(path, &times), path);
}


static int FgetID(lua_State *L, int i, const void *data)
{
	switch (i)
	{
		case 0:	lua_pushnumber(L, getegid());	break;
		case 1:	lua_pushnumber(L, geteuid());	break;
		case 2:	lua_pushnumber(L, getgid());	break;
		case 3:	lua_pushnumber(L, getuid());	break;
		case 4:	lua_pushnumber(L, getpgrp());	break;
		case 5:	lua_pushnumber(L, getpid());	break;
		case 6:	lua_pushnumber(L, getppid());	break;
	}
	return 1;
}

static const char *const SgetID[] =
{
	"egid", "euid", "gid", "uid", "pgrp", "pid", "ppid", NULL
};

static int Pgetprocessid(lua_State *L)		/** getprocessid([selector]) */
{
	return doselection(L, 1, SgetID, FgetID, NULL);
}


static int Pttyname(lua_State *L)		/** ttyname(fd) */
{
	int fd=luaL_optinteger(L, 1, 0);
	lua_pushstring(L, ttyname(fd));
	return 1;
}

static int Pctermid(lua_State *L)		/** ctermid() */
{
	char b[L_ctermid];
	lua_pushstring(L, ctermid(b));
	return 1;
}


static int Pgetlogin(lua_State *L)		/** getlogin() */
{
	lua_pushstring(L, getlogin());
	return 1;
}


static int Fgetpasswd(lua_State *L, int i, const void *data)
{
	const struct passwd *p= (const struct passwd *)data;
	switch (i)
	{
		case 0: lua_pushstring(L, p->pw_name); break;
		case 1: lua_pushnumber(L, p->pw_uid); break;
		case 2: lua_pushnumber(L, p->pw_gid); break;
		case 3: lua_pushstring(L, p->pw_dir); break;
		case 4: lua_pushstring(L, p->pw_shell); break;
/* not strictly POSIX */
		case 5: lua_pushstring(L, p->pw_gecos); break;
		case 6: lua_pushstring(L, p->pw_passwd); break;
	}
	return 1;
}

static const char *const Sgetpasswd[] =
{
	"name", "uid", "gid", "dir", "shell", "gecos", "passwd", NULL
};


static int Pgetpasswd(lua_State *L)		/** getpasswd(name or id) */
{
	struct passwd *p=NULL;
	if (lua_isnoneornil(L, 1))
		p = getpwuid(geteuid());
	else if (lua_isnumber(L, 1))
		p = getpwuid((uid_t)lua_tonumber(L, 1));
	else if (lua_isstring(L, 1))
		p = getpwnam(lua_tostring(L, 1));
	else
		typerror(L, 1, "string or number");
	if (p==NULL)
		lua_pushnil(L);
	else
		doselection(L, 2, Sgetpasswd, Fgetpasswd, p);
	return 1;
}


static int Pgetgroup(lua_State *L)		/** getgroup(name or id) */
{
	struct group *g=NULL;
	if (lua_isnumber(L, 1))
		g = getgrgid((gid_t)lua_tonumber(L, 1));
	else if (lua_isstring(L, 1))
		g = getgrnam(lua_tostring(L, 1));
	else
		typerror(L, 1, "string or number");
	if (g==NULL)
		lua_pushnil(L);
	else
	{
		int i;
		lua_newtable(L);
		storestring(L, "name", g->gr_name);
		storenumber(L, "gid", g->gr_gid);
		for (i=0; g->gr_mem[i] != NULL; i++)
			storeindex(L, i+1, g->gr_mem[i]);
	}
	return 1;
}


static int Psetuid(lua_State *L)		/** setuid(name or id) */
{
	return pushresult(L, setuid(mygetuid(L, 1)), NULL);
}


static int Psetgid(lua_State *L)		/** setgid(name or id) */
{
	return pushresult(L, setgid(mygetgid(L, 1)), NULL);
}

struct mytimes
{
 struct tms t;
 clock_t elapsed;
};

#define pushtime(L,x)		lua_pushnumber(L,((lua_Number)x)/CLOCKS_PER_SEC)

static int Ftimes(lua_State *L, int i, const void *data)
{
	const struct mytimes *t=(const struct mytimes *)data;
	switch (i)
	{
		case 0: pushtime(L, t->t.tms_utime); break;
		case 1: pushtime(L, t->t.tms_stime); break;
		case 2: pushtime(L, t->t.tms_cutime); break;
		case 3: pushtime(L, t->t.tms_cstime); break;
		case 4: pushtime(L, t->elapsed); break;
	}
	return 1;
}

static const char *const Stimes[] =
{
	"utime", "stime", "cutime", "cstime", "elapsed", NULL
};

#define storetime(L,name,x)	storenumber(L,name,(lua_Number)x/CLOCKS_PER_SEC)

static int Ptimes(lua_State *L)			/** times() */
{
	struct mytimes t;
	t.elapsed = times(&t.t);
	return doselection(L, 1, Stimes, Ftimes, &t);
}


struct mystat
{
	struct stat s;
	char mode[10];
	const char *type;
};

static int Fstat(lua_State *L, int i, const void *data)
{
	const struct mystat *s=(const struct mystat *)data;
	switch (i)
	{
		case 0: lua_pushstring(L, s->mode); break;
		case 1: lua_pushnumber(L, s->s.st_ino); break;
		case 2: lua_pushnumber(L, s->s.st_dev); break;
		case 3: lua_pushnumber(L, s->s.st_nlink); break;
		case 4: lua_pushnumber(L, s->s.st_uid); break;
		case 5: lua_pushnumber(L, s->s.st_gid); break;
		case 6: lua_pushnumber(L, s->s.st_size); break;
		case 7: lua_pushnumber(L, s->s.st_atime); break;
		case 8: lua_pushnumber(L, s->s.st_mtime); break;
		case 9: lua_pushnumber(L, s->s.st_ctime); break;
		case 10:lua_pushstring(L, s->type); break;
		case 11:lua_pushnumber(L, s->s.st_mode); break;
	}
	return 1;
}

static const char *const Sstat[] =
{
	"mode", "ino", "dev", "nlink", "uid", "gid",
	"size", "atime", "mtime", "ctime", "type", "_mode",
	NULL
};

static int Pstat(lua_State *L)			/** stat(path,[selector]) */
{
	struct mystat s;
	const char *path=luaL_checkstring(L, 1);
	if (lstat(path,&s.s)==-1) return pusherror(L, path);
	s.type=filetype(s.s.st_mode);
	modechopper(s.s.st_mode, s.mode);
	return doselection(L, 2, Sstat, Fstat, &s);
}


static int Puname(lua_State *L)			/** uname([string]) */
{
	struct utsname u;
	luaL_Buffer b;
	const char *s;
	if (uname(&u) == -1) return pusherror(L, NULL);
	luaL_buffinit(L, &b);
	for (s=luaL_optstring(L, 1, "%s %n %r %v %m"); *s; s++)
		if (*s!='%')
			luaL_addchar(&b, *s);
		else switch (*++s)
		{
			case '%': luaL_addchar(&b, *s); break;
			case 'm': luaL_addstring(&b,u.machine); break;
			case 'n': luaL_addstring(&b,u.nodename); break;
			case 'r': luaL_addstring(&b,u.release); break;
			case 's': luaL_addstring(&b,u.sysname); break;
			case 'v': luaL_addstring(&b,u.version); break;
			default: badoption(L, 2, "format", *s); break;
		}
	luaL_pushresult(&b);
	return 1;
}


static const int Kpathconf[] =
{
	_PC_LINK_MAX, _PC_MAX_CANON, _PC_MAX_INPUT, _PC_NAME_MAX, _PC_PATH_MAX,
	_PC_PIPE_BUF, _PC_CHOWN_RESTRICTED, _PC_NO_TRUNC, _PC_VDISABLE,
	-1
};

static int Fpathconf(lua_State *L, int i, const void *data)
{
	const char *path=(const char *)data;
	lua_pushnumber(L, pathconf(path, Kpathconf[i]));
	return 1;
}

static const char *const Spathconf[] =
{
	"link_max", "max_canon", "max_input", "name_max", "path_max",
	"pipe_buf", "chown_restricted", "no_trunc", "vdisable",
	NULL
};

static int Ppathconf(lua_State *L)		/** pathconf(path,[selector]) */
{
	const char *path=luaL_checkstring(L, 1);
	return doselection(L, 2, Spathconf, Fpathconf, path);
}


static const int Ksysconf[] =
{
	_SC_ARG_MAX, _SC_CHILD_MAX, _SC_CLK_TCK, _SC_NGROUPS_MAX, _SC_STREAM_MAX,
	_SC_TZNAME_MAX, _SC_OPEN_MAX, _SC_JOB_CONTROL, _SC_SAVED_IDS, _SC_VERSION,
	-1
};

static int Fsysconf(lua_State *L, int i, const void *data)
{
	lua_pushnumber(L, sysconf(Ksysconf[i]));
	return 1;
}

static const char *const Ssysconf[] =
{
	"arg_max", "child_max", "clk_tck", "ngroups_max", "stream_max",
	"tzname_max", "open_max", "job_control", "saved_ids", "version",
	NULL
};

static int Psysconf(lua_State *L)		/** sysconf([selector]) */
{
	return doselection(L, 1, Ssysconf, Fsysconf, NULL);
}

static int Pmkstemp(lua_State *L)
{
	const char *path;
	char *dynpath;
	int fd;
	FILE **f;

	path = luaL_checkstring(L, 1);
	if (path == NULL)
		return 0;
	dynpath = rstrdup(path);
	fd = mkstemp(dynpath);
	f = (FILE**)lua_newuserdata(L, sizeof(FILE*));
	if (f == NULL) {
		close(fd);
		free(dynpath);
		return 0;
	}
	*f = fdopen(fd, "a+");
	lua_pushstring(L, dynpath);
	free(dynpath);
	luaL_getmetatable(L, "FILE*");
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return luaL_error(L, "FILE* metatable not available "
			      "(io not loaded?)");
	} else {
		lua_setmetatable(L, -3);
	}
	return 2;
}

static const luaL_Reg R[] =
{
	{"access",		Paccess},
	{"chdir",		Pchdir},
	{"chmod",		Pchmod},
	{"chown",		Pchown},
	{"ctermid",		Pctermid},
	{"dir",			Pdir},
	{"errno",		Perrno},
	{"exec",		Pexec},
	{"files",		Pfiles},
	{"fork",		Pfork},
	{"getcwd",		Pgetcwd},
	{"getenv",		Pgetenv},
	{"getgroup",		Pgetgroup},
	{"getlogin",		Pgetlogin},
	{"getpasswd",		Pgetpasswd},
	{"getprocessid",	Pgetprocessid},
	{"kill",		Pkill},
	{"link",		Plink},
	{"mkdir",		Pmkdir},
	{"mkfifo",		Pmkfifo},
	{"mkstemp",		Pmkstemp},
	{"pathconf",		Ppathconf},
	{"putenv",		Pputenv},
	{"readlink",		Preadlink},
	{"rmdir",		Prmdir},
	{"setgid",		Psetgid},
	{"setuid",		Psetuid},
	{"sleep",		Psleep},
	{"stat",		Pstat},
	{"symlink",		Psymlink},
	{"sysconf",		Psysconf},
	{"times",		Ptimes},
	{"ttyname",		Pttyname},
	{"umask",		Pumask},
	{"uname",		Puname},
	{"unlink",		Punlink},
	{"utime",		Putime},
	{"wait",		Pwait},
	{"setenv",		Psetenv},
	{"unsetenv",		Punsetenv},
	{NULL,			NULL}
};

LUALIB_API int luaopen_posix (lua_State *L)
{
	luaL_newlib(L, R);
	lua_pushliteral(L,"version");		/** version */
	lua_pushliteral(L,MYVERSION);
	lua_settable(L,-3);
	return 1;
}

