/** \ingroup rpmio
 * \file rpmio/url.c
 */

#include "system.h"

#include <sys/wait.h>

#include <rpm/rpmmacro.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmurl.h>
#include <rpm/rpmio.h>
#include <rpm/argv.h>
#include <rpm/rpmstring.h>

#include "debug.h"

/**
 */
static struct urlstring {
    const char * leadin;
    urltype	ret;
} const urlstrings[] = {
    { "file://",	URL_IS_PATH },
    { "ftp://",		URL_IS_FTP },
    { "hkp://",		URL_IS_HKP },
    { "http://",	URL_IS_HTTP },
    { "https://",	URL_IS_HTTPS },
    { NULL,		URL_IS_UNKNOWN }
};

urltype urlIsURL(const char * url)
{
    const struct urlstring *us;

    if (url && *url) {
	for (us = urlstrings; us->leadin != NULL; us++) {
	    if (!rstreqn(url, us->leadin, strlen(us->leadin)))
		continue;
	    return us->ret;
	}
	if (rstreq(url, "-")) 
	    return URL_IS_DASH;
    }

    return URL_IS_UNKNOWN;
}

/* Return path portion of url (or pointer to NUL if url == NULL) */
urltype urlPath(const char * url, const char ** pathp)
{
    const char *path;
    urltype type;

    path = url;
    type = urlIsURL(url);
    switch (type) {
    case URL_IS_FTP:
	url += sizeof("ftp://") - 1;
	path = strchr(url, '/');
	if (path == NULL) path = url + strlen(url);
	break;
    case URL_IS_PATH:
	url += sizeof("file://") - 1;
	path = strchr(url, '/');
	if (path == NULL) path = url + strlen(url);
	break;
    case URL_IS_HKP:
	url += sizeof("hkp://") - 1;
	path = strchr(url, '/');
	if (path == NULL) path = url + strlen(url);
	break;
    case URL_IS_HTTP:
	url += sizeof("http://") - 1;
	path = strchr(url, '/');
	if (path == NULL) path = url + strlen(url);
	break;
    case URL_IS_HTTPS:
	url += sizeof("https://") - 1;
	path = strchr(url, '/');
	if (path == NULL) path = url + strlen(url);
	break;
    case URL_IS_UNKNOWN:
	if (path == NULL) path = "";
	break;
    case URL_IS_DASH:
	path = "";
	break;
    }
    if (pathp)
	*pathp = path;
    return type;
}

int urlGetFile(const char * url, const char * dest)
{
    char *cmd = NULL;
    const char *target = NULL;
    char *urlhelper = NULL;
    int status;
    pid_t pid;
    int res = -1;

    urlhelper = rpmExpand("%{?_urlhelper}", NULL);

    if (dest == NULL) {
	urlPath(url, &target);
    } else {
	target = dest;
    }

    /* XXX TODO: sanity checks like target == dest... */

    rasprintf(&cmd, "%s %s %s", urlhelper, target, url);

    if ((pid = fork()) == 0) {
        ARGV_t argv = NULL;
        argvSplit(&argv, cmd, " ");
        execvp(argv[0], argv);
        exit(127); /* exit with 127 for compatibility with bash(1) */
    }

    if ((waitpid(pid, &status, 0) != -1) && WIFEXITED(status)) {
	if (WEXITSTATUS(status) == 127)
	    rpmlog(RPMLOG_ERR, _("Could not find url helper: \"%s\"\n"), urlhelper);
	else if (WEXITSTATUS(status) == 0)
	    res = 0;
	else
	    rpmlog(RPMLOG_ERR, _("Executing url helper \"%s\" failed with status %i\n"), cmd, WEXITSTATUS(status));
    }

    free(cmd);
    free(urlhelper);
    return res;
}
