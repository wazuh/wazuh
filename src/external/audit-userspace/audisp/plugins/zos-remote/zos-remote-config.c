/***************************************************************************
 *   Copyright (C) 2007 International Business Machines  Corp.             *
 *   All Rights Reserved.                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                         *
 * Authors:                                                                *
 *   Klaus Heinrich Kiwi <klausk@br.ibm.com>                               *
 *   based on code by Steve Grubb <sgrubb@redhat.com>                      *
 ***************************************************************************/

#include "zos-remote-config.h"

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include "zos-remote-log.h"

/* Local prototypes */
struct nv_pair
{
        const char *name;
        const char *value;
        const char *option;
};

struct kw_pair
{
        const char *name;
        int (*parser) (struct nv_pair *, int, plugin_conf_t *);
        int max_options;
};

struct nv_list
{
        const char *name;
        int option;
};

static char *get_line(FILE *, char *);
static int nv_split(char *, struct nv_pair *);
static const struct kw_pair *kw_lookup(const char *);
static int server_parser(struct nv_pair *, int, plugin_conf_t *);
static int port_parser(struct nv_pair *, int, plugin_conf_t *);
static int timeout_parser(struct nv_pair *, int, plugin_conf_t *);
static int user_parser(struct nv_pair *, int, plugin_conf_t *);
static int password_parser(struct nv_pair *, int, plugin_conf_t *);
static int q_depth_parser(struct nv_pair *, int, plugin_conf_t *);
static int sanity_check(plugin_conf_t *);

static const struct kw_pair keywords[] = {
        {"server", server_parser, 0},
        {"port", port_parser, 0},
        {"timeout", timeout_parser, 0},
        {"user", user_parser, 0},
        {"password", password_parser, 0},
        {"q_depth", q_depth_parser, 0},
        {NULL, NULL, 0}
};

#define UNUSED(x) (void)(x)

/*
 * Set everything to its default value
*/
void plugin_clear_config(plugin_conf_t * c)
{
        c->server = NULL;
        c->port = 0;
        c->user = NULL;
        c->password = NULL;
        c->timeout = 15;
        c->q_depth = 64;
        /* not re-setting counter */
}

int plugin_load_config(plugin_conf_t * c, const char *file)
{
        int fd, rc, mode, lineno = 1;
        struct stat st;
        FILE *f;
        char buf[128];

        plugin_clear_config(c);

        /* open the file */
        mode = O_RDONLY;
        rc = open(file, mode);
        if (rc < 0) {
                if (errno != ENOENT) {
                        log_err("Error opening %s (%s)", file,
                                strerror(errno));
                        return 1;
                }
                log_warn("Config file %s doesn't exist, skipping", file);
                return 1;
        }
        fd = rc;

        /* check the file's permissions: owned by root, not world anything,
         * not symlink.
         */
        if (fstat(fd, &st) < 0) {
                log_err("Error fstat'ing config file (%s)",
                        strerror(errno));
                close(fd);
                return 1;
        }
        if (st.st_uid != 0) {
                log_err("Error - %s isn't owned by root", file);
                close(fd);
                return 1;
        }
        if ((st.st_mode & (S_IRUSR | S_IWUSR | S_IRGRP)) !=
            (S_IRUSR | S_IWUSR | S_IRGRP)) {
                log_err("%s permissions should be 0640", file);
                close(fd);
                return 1;
        }
        if (!S_ISREG(st.st_mode)) {
                log_err("Error - %s is not a regular file", file);
                close(fd);
                return 1;
        }

        /* it's ok, read line by line */
        f = fdopen(fd, "r");
        if (f == NULL) {
                log_err("Error - fdopen failed (%s)", strerror(errno));
                close(fd);
                return 1;
        }

        while (get_line(f, buf)) {
                /* convert line into name-value pair */
                const struct kw_pair *kw;
                struct nv_pair nv;

                rc = nv_split(buf, &nv);
                switch (rc) {
                case 0:        /* fine */
                        break;
                case 1:        /* not the right number of tokens. */
                        log_err("Wrong number of arguments for line %d in %s", lineno, file);
                        break;
                case 2:        /* no '=' sign */
                        log_err("Missing equal sign for line %d in %s",
                                lineno, file);
                        break;
                default:       /* something else went wrong... */
                        log_err("Unknown error for line %d in %s",
                                lineno, file);
                        break;
                }
                if (nv.name == NULL) {
                        lineno++;
                        continue;
                }
                if (nv.value == NULL) {
                        fclose(f);
                        return 1;
                }

                /* identify keyword or error */
                kw = kw_lookup(nv.name);
                if (kw->name == NULL) {
                        log_err("Unknown keyword \"%s\" in line %d of %s",
                                nv.name, lineno, file);
                        fclose(f);
                        return 1;
                }

                /* Check number of options */
                if (kw->max_options == 0 && nv.option != NULL) {
                        log_err("Keyword \"%s\" has invalid option "
                                "\"%s\" in line %d of %s",
                                nv.name, nv.option, lineno, file);
                        fclose(f);
                        return 1;
                }

                /* dispatch to keyword's local parser */
                rc = kw->parser(&nv, lineno, c);
                if (rc != 0) {
                        fclose(f);
                        return 1;       /* local parser puts message out */
                }

                lineno++;
        }

        fclose(f);
        c->name = strdup(basename(file));
        if (lineno > 1)
                return sanity_check(c);
        return 0;
}

static char *get_line(FILE * f, char *buf)
{
        if (fgets_unlocked(buf, 128, f)) {
                /* remove newline */
                char *ptr = strchr(buf, 0x0a);

                if (ptr)
                        *ptr = 0;
                return buf;
        }
        return NULL;
}

static int nv_split(char *buf, struct nv_pair *nv)
{
        /* Get the name part */
        char *ptr, *saved;

        nv->name = NULL;
        nv->value = NULL;
        nv->option = NULL;
        ptr = strtok_r(buf, " ", &saved);
        if (ptr == NULL)
                return 0;       /* If there's nothing, go to next line */
        if (ptr[0] == '#')
                return 0;       /* If there's a comment, go to next line */
        nv->name = ptr;

        /* Check for a '=' */
        ptr = strtok_r(NULL, " ", &saved);
        if (ptr == NULL)
                return 1;
        if (strcmp(ptr, "=") != 0)
                return 2;

        /* get the value */
        ptr = strtok_r(NULL, " ", &saved);
        if (ptr == NULL)
                return 1;
        nv->value = ptr;

        /* See if there's an option */
        ptr = strtok_r(NULL, " ", &saved);
        if (ptr) {
                nv->option = ptr;

                /* Make sure there's nothing else */
                ptr = strtok_r(NULL, " ", &saved);
                if (ptr)
                        return 1;
        }

        /* Everything is OK */
        return 0;
}

static const struct kw_pair *kw_lookup(const char *val)
{
        int i = 0;

        while (keywords[i].name != NULL) {
                if (strcasecmp(keywords[i].name, val) == 0)
                        break;
                i++;
        }
        return &keywords[i];
}


static int server_parser(struct nv_pair *nv, int line, plugin_conf_t * c)
{
	UNUSED(line);
        if (nv->value == NULL)
                c->server = NULL;
        else
                c->server = strdup(nv->value);

        return 0;
}

static int port_parser(struct nv_pair *nv, int line, plugin_conf_t * c)
{
        const char *ptr = nv->value;
        unsigned long i;

        /* check that all chars are numbers */
        for (i = 0; ptr[i]; i++) {
                if (!isdigit(ptr[i])) {
                        log_err("Value %s should only be numbers - line %d", nv->value, line);
                        return 1;
                }
        }

        /* convert to unsigned long */
        errno = 0;
        i = strtoul(nv->value, NULL, 10);
        if (errno) {
                log_err("Error converting string to a number (%s) - line %d", strerror(errno), line);
                return 1;
        }

        c->port = i;
        return 0;

}

static int timeout_parser(struct nv_pair *nv, int line, plugin_conf_t * c)
{
        const char *ptr = nv->value;
        unsigned long i;

        /* check that all chars are numbers */
        for (i = 0; ptr[i]; i++) {
                if (!isdigit(ptr[i])) {
                        log_err("Value %s should only be numbers - line %d", nv->value, line);
                        return 1;
                }
        }

        /* convert to unsigned long */
        errno = 0;
        i = strtoul(nv->value, NULL, 10);
        if (errno) {
                log_err("Error converting string to a number (%s) - line %d", strerror(errno), line);
                return 1;
        }

        c->timeout = i;
        return 0;

}


static int user_parser(struct nv_pair *nv, int line, plugin_conf_t * c)
{
	UNUSED(line);
        if (nv->value == NULL)
                c->user = NULL;
        else
                c->user = strdup(nv->value);

        return 0;
}

static int password_parser(struct nv_pair *nv, int line, plugin_conf_t * c)
{
	UNUSED(line);
        if (nv->value == NULL)
                c->password = NULL;
        else
                c->password = strdup(nv->value);

        return 0;
}

static int q_depth_parser(struct nv_pair *nv, int line, plugin_conf_t * c)
{
        const char *ptr = nv->value;
        unsigned long i;

        /* check that all chars are numbers */
        for (i = 0; ptr[i]; i++) {
                if (!isdigit(ptr[i])) {
                        log_err("Value %s should only be numbers - line %d", nv->value, line);
                        return 1;
                }
        }

        /* convert to unsigned long */
        errno = 0;
        i = strtoul(nv->value, NULL, 10);
        if (errno) {
                log_err("Error converting string to a number (%s) - line %d", strerror(errno), line);
                return 1;
        }
        
        if (i < 16 || i > 99999) {
                log_err("q_depth must be between 16 and 99999");
                return 1;
        }

        c->q_depth = i;
        return 0;

}


/*
 * Check configuration.At this point, all fields have been read. 
 * Returns 0 if no problems and 1 if problems detected.
 */
static int sanity_check(plugin_conf_t * c)
{
        /* Error checking */
        if (!c->server) {
                log_err("Error - no server hostname given");
                return 1;
        }

        if (!c->user) {
                log_err("Error - no bind user given");
                return 1;
        }

        if (!c->password) {
                log_err("Error - no password given");
                return 1;
        }
        
        if (!c->timeout) {
                log_err("Error - timeout can't be zero");
                return 1;
        }
        return 0;
}

void plugin_free_config(plugin_conf_t * c)
{

        if (c == NULL)
                return;

        free((void *) c->server);
        free((void *) c->user);
        free((void *) c->password);
        free((void *) c->name);
}
