/*
* ausearch-lookup.c - Lookup values to something more readable
* Copyright (c) 2005-06,2011-12,2015-17 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved. 
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
* Boston, MA 02110-1335, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <linux/net.h>
#include "ausearch-lookup.h"
#include "ausearch-options.h"
#include "ausearch-nvpair.h"
#include "auparse-idata.h"

/* This is the name/value pair used by search tables */
struct nv_pair {
	int        value;
	const char *name;
};


/* The machine based on elf type */
static int machine = 0;
static const char *Q = "?";
static const char *results[3]= { "unset", "denied", "granted" };
static const char *success[3]= { "unset", "no", "yes" };
static const char *aulookup_socketcall(long sc);
static const char *aulookup_ipccall(long ic);

const char *aulookup_result(avc_t result)
{
	return results[result];
}

const char *aulookup_success(int s)
{
	switch (s)
	{
		default:
			return success[0];
			break;
		case S_FAILED:
			return success[1];
			break;
		case S_SUCCESS:
			return success[2];
			break;
	}
}

const char *aulookup_syscall(llist *l, char *buf, size_t size)
{
	const char *sys;

	if (report_format <= RPT_DEFAULT) {
		snprintf(buf, size, "%d", l->s.syscall);
		return buf;
	}

	sys = _auparse_lookup_interpretation("syscall");
	if (sys) {
		snprintf(buf, size, "%s", sys);
		free((void *)sys);
		return buf;
	}

	machine = audit_elf_to_machine(l->s.arch);
	if (machine < 0)
		return Q;
	sys = audit_syscall_to_name(l->s.syscall, machine);
	if (sys) {
		const char *func = NULL;
		if (strcmp(sys, "socketcall") == 0) {
			if (list_find_item(l, AUDIT_SYSCALL))
				func = aulookup_socketcall((long)l->cur->a0);
		} else if (strcmp(sys, "ipc") == 0) {
			if(list_find_item(l, AUDIT_SYSCALL))
				func = aulookup_ipccall((long)l->cur->a0);
		}
		if (func) {
			snprintf(buf, size, "%s(%s)", sys, func);
			return buf;
		}
		snprintf(buf, size, "%s", sys);
		return buf;
	}
	snprintf(buf, size, "%d", l->s.syscall);
	return buf;
}

// See include/linux/net.h
static struct nv_pair socktab[] = {
	{SYS_SOCKET, "socket"},
	{SYS_BIND, "bind"},
	{SYS_CONNECT, "connect"},
	{SYS_LISTEN, "listen"},
	{SYS_ACCEPT, "accept"},
	{SYS_GETSOCKNAME, "getsockname"},
	{SYS_GETPEERNAME, "getpeername"},
	{SYS_SOCKETPAIR, "socketpair"},
	{SYS_SEND, "send"},
	{SYS_RECV, "recv"},
	{SYS_SENDTO, "sendto"},
	{SYS_RECVFROM, "recvfrom"},
	{SYS_SHUTDOWN, "shutdown"},
	{SYS_SETSOCKOPT, "setsockopt"},
	{SYS_GETSOCKOPT, "getsockopt"},
	{SYS_SENDMSG, "sendmsg"},
	{SYS_RECVMSG, "recvmsg"},
	{SYS_ACCEPT4, "accept4"},
	{19, "recvmmsg"},
	{20, "sendmmsg"}
};
#define SOCK_NAMES (sizeof(socktab)/sizeof(socktab[0]))

static const char *aulookup_socketcall(long sc)
{
        unsigned int i;

        for (i = 0; i < SOCK_NAMES; i++)
                if (socktab[i].value == sc)
                        return socktab[i].name;

        return NULL;
}

/* This is from asm/ipc.h. Copying it for now as some platforms
 * have broken headers. */
#define SEMOP            1
#define SEMGET           2
#define SEMCTL           3
#define SEMTIMEDOP	 4
#define MSGSND          11
#define MSGRCV          12
#define MSGGET          13
#define MSGCTL          14
#define SHMAT           21
#define SHMDT           22
#define SHMGET          23
#define SHMCTL          24

/*
 * This table maps ipc calls to their text name
 */
static struct nv_pair ipctab[] = {
        {SEMOP, "semop"},
        {SEMGET, "semget"},
        {SEMCTL, "semctl"},
        {SEMTIMEDOP, "semtimedop"},
        {MSGSND, "msgsnd"},
        {MSGRCV, "msgrcv"},
        {MSGGET, "msgget"},
        {MSGCTL, "msgctl"},
        {SHMAT, "shmat"},
        {SHMDT, "shmdt"},
        {SHMGET, "shmget"},
        {SHMCTL, "shmctl"}
};
#define IPC_NAMES (sizeof(ipctab)/sizeof(ipctab[0]))

static const char *aulookup_ipccall(long ic)
{
        unsigned int i;

        for (i = 0; i < IPC_NAMES; i++)
                if (ipctab[i].value == ic)
                        return ipctab[i].name;

        return NULL;
} 

static nvlist uid_nvl;
static int uid_list_created=0;
const char *aulookup_uid(uid_t uid, char *buf, size_t size)
{
	const char *name;
	int rc;

	if (report_format <= RPT_DEFAULT) {
		snprintf(buf, size, "%d", uid);
		return buf;
	}
	if (uid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	}

	name = _auparse_lookup_interpretation("auid");
	if (name) {
		snprintf(buf, size, "%s", name);
		free((void *)name);
		return buf;
	}

	// Check the cache first
	if (uid_list_created == 0) {
		nvlist_create(&uid_nvl);
		nvlist_clear(&uid_nvl);
		uid_list_created = 1;
	}
	rc = nvlist_find_val(&uid_nvl, uid);
	if (rc) {
		name = uid_nvl.cur->name;
	} else {
		// This getpw use is OK because its for protocol 1 compatibility
		// Add it to cache
		struct passwd *pw;
		pw = getpwuid(uid);
		if (pw) {
			nvnode nv;
			nv.name = strdup(pw->pw_name);
			nv.val = uid;
			nvlist_append(&uid_nvl, &nv);
			name = uid_nvl.cur->name;
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", uid);
	return buf;
}

void aulookup_destroy_uid_list(void)
{
	if (uid_list_created == 0)
		return;

	nvlist_clear(&uid_nvl); 
	uid_list_created = 0;
}

int is_hex_string(const char *str)
{
	int c=0;
	while (*str) {
		if (!isxdigit(*str))
			return 0;
		str++;
		c++;
	}
	return 1;
}
/*
 * This function will take a pointer to a 2 byte Ascii character buffer and 
 * return the actual hex value.
 */
static unsigned char x2c(unsigned char *buf)
{
	static const char AsciiArray[17] = "0123456789ABCDEF";
	char *ptr;
	unsigned char total=0;

	ptr = strchr(AsciiArray, (char)toupper(buf[0]));
	if (ptr)
		total = (unsigned char)(((ptr-AsciiArray) & 0x0F)<<4);
	ptr = strchr(AsciiArray, (char)toupper(buf[1]));
	if (ptr)
		total += (unsigned char)((ptr-AsciiArray) & 0x0F);

	return total;
}

/* returns a freshly malloc'ed and converted buffer */
char *unescape(const char *buf)
{
	int len, i;
	char *str, *strptr;
	const char *ptr = buf;

	/* Find the end of the name */
	if (*ptr == '(') {
		ptr = strchr(ptr, ')');
		if (ptr == NULL)
			return NULL;
		else
			ptr++;
	} else {
		while (isxdigit(*ptr))
			ptr++;
	}
	str = strndup(buf, ptr - buf);

	if (*buf == '(')
		return str;

	/* We can get away with this since the buffer is 2 times
	 * bigger than what we are putting there.
	 */
	len = strlen(str);
	if (len < 2) {
		free(str);
		return NULL;
	}
	strptr = str;
	for (i=0; i<len; i+=2) {
		*strptr = x2c((unsigned char *)&str[i]);
		strptr++;
	}
	*strptr = 0;
	return str;
}

static int need_tty_escape(const unsigned char *s, unsigned int len)
{
	unsigned int i = 0;
	while (i < len) {
		if (s[i] < 32)
			return 1;
		i++;
	}
	return 0;
}

static void tty_escape(const char *s, unsigned int len)
{
	unsigned int i = 0;
	while (i < len) {
		if ((unsigned char)s[i] < 32) {
			putchar('\\');
			putchar('0' + ((s[i] & 0300) >> 6));
			putchar('0' + ((s[i] & 0070) >> 3));
			putchar('0' + (s[i] & 0007));
		} else
			putchar(s[i]);
		i++;
	}
}

static const char sh_set[] = "\"'`$\\!()| ";
static unsigned int need_shell_escape(const char *s, unsigned int len)
{
	unsigned int i = 0, cnt = 0;
	while (i < len) {
		if (s[i] < 32)
			cnt++;
		else if (strchr(sh_set, s[i]))
			cnt++;
		i++;
	}
	return cnt;
}

static void shell_escape(const char *s, unsigned int len)
{
	unsigned int i = 0;
	while (i < len) {
		if ((unsigned char)s[i] < 32) {
			putchar('\\');
			putchar('0' + ((s[i] & 0300) >> 6));
			putchar('0' + ((s[i] & 0070) >> 3));
			putchar('0' + (s[i] & 0007));
		} else if (strchr(sh_set, s[i])) {
			putchar('\\');
			putchar(s[i]);
		} else
			putchar(s[i]);
		i++;
	}
}

static const char quote_set[] = "\"'`$\\!()| ;#&*?[]<>{}";
static unsigned int need_shell_quote_escape(const unsigned char *s, unsigned int len)
{
	unsigned int i = 0, cnt = 0;
	while (i < len) {
		if (s[i] < 32)
			cnt++;
		else if (strchr(quote_set, s[i]))
			cnt++;
		i++;
	}
	return cnt;
}

static void shell_quote_escape(const char *s, unsigned int len)
{
	unsigned int i = 0;
	while (i < len) {
		if ((unsigned char)s[i] < 32) {
			putchar('\\');
			putchar('0' + ((s[i] & 0300) >> 6));
			putchar('0' + ((s[i] & 0070) >> 3));
			putchar('0' + (s[i] & 0007));
		} else if (strchr(quote_set, s[i])) {
			putchar('\\');
			putchar(s[i]);
		} else
			putchar(s[i]);
		i++;
	}
}

static unsigned int need_escaping(const char *s, unsigned int len)
{
	switch (escape_mode)
	{
		case AUPARSE_ESC_RAW:
			break;
		case AUPARSE_ESC_TTY:
			return need_tty_escape(s, len);
		case AUPARSE_ESC_SHELL:
			return need_shell_escape(s, len);
		case AUPARSE_ESC_SHELL_QUOTE:
			return need_shell_quote_escape(s, len);
	}
	return 0;
}

static void escape(const char *s, unsigned int len)
{
	switch (escape_mode)
	{
		case AUPARSE_ESC_RAW:
			return;
		case AUPARSE_ESC_TTY:
			return tty_escape(s, len);
		case AUPARSE_ESC_SHELL:
			return shell_escape(s, len);
		case AUPARSE_ESC_SHELL_QUOTE:
			return shell_quote_escape(s, len);
	}
}

void safe_print_string_n(const char *s, unsigned int len, int ret)
{
	if (len > MAX_AUDIT_MESSAGE_LENGTH)
		len = MAX_AUDIT_MESSAGE_LENGTH;

	if (need_escaping(s, len)) {
		escape(s, len);
		if (ret)
			putchar('\n');
	} else if (ret)
		puts(s);
	else
		printf("%s", s);
}

void safe_print_string(const char *s, int ret)
{
	safe_print_string_n(s, strlen(s), ret);
}

/* Represent c as a character within a quoted string, and append it to buf. */
static void tty_printable_char(unsigned char c)
{
	if (c < 0x20 || c > 0x7E) {
		putchar('\\');
		putchar('0' + ((c >> 6) & 07));
		putchar('0' + ((c >> 3) & 07));
		putchar('0' + (c & 07));
	} else {
		if (c == '\\' || c ==  '"')
			putchar('\\');
		putchar(c);
	}
}

/* Search for a name of a sequence of TTY bytes.
 *  If found, return the name and advance *INPUT.
 *  Return NULL otherwise. 
 */
static const char *tty_find_named_key(unsigned char **input, size_t input_len)
{
	/* NUL-terminated list of (sequence, NUL, name, NUL) entries.
	   First match wins, even if a longer match were possible later */
	static const unsigned char named_keys[] =
#define E(SEQ, NAME) SEQ "\0" NAME "\0"
#include "auparse/tty_named_keys.h"
#undef E
	"\0";

	unsigned char *src;
	const unsigned char *nk;

	src = *input;
	if (*src >= ' ' && (*src < 0x7F || *src >= 0xA0))
		return NULL; /* Fast path */
	nk = named_keys;
	do {
		const unsigned char *p;
		size_t nk_len;

		p = strchr((const char *)nk, '\0');
		nk_len = p - nk;
		if (nk_len <= input_len && memcmp(src, nk, nk_len) == 0) {
			*input += nk_len;
			return (const char *)(p + 1);
		}
		nk = strchr((const char *)p + 1, '\0') + 1;
	} while (*nk != '\0');
	return NULL;
}

void print_tty_data(const char *val)
{
	int need_comma, in_printable = 0;
	unsigned char *data, *data_pos, *data_end;

	if (!is_hex_string(val)) {
		printf("%s", val);
		return;
	}

	if ((data = unescape((char *)val)) == NULL) {
		printf("conversion error(%s)", val);
		return;
	}

	data_end = data + strlen(val) / 2;
	data_pos = data;
	need_comma = 0;
	while (data_pos < data_end) {
		/* FIXME: Unicode */
		const char *desc;

		desc = tty_find_named_key(&data_pos, data_end - data_pos);
		if (desc != NULL) {
			if (in_printable != 0) {
				putchar('"');
				in_printable = 0;
			}
			if (need_comma != 0)
				putchar(',');
			printf("<%s>", desc);
		} else {
			if (in_printable == 0) {
				if (need_comma != 0)
					putchar(',');
				putchar('"');
				in_printable = 1;
			}
			tty_printable_char(*data_pos);
			data_pos++;
		}
		need_comma = 1;
	}
	if (in_printable != 0)
		putchar('"');
	free(data);
}

