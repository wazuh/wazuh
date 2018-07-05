/* audisp-prelude.c --
 * Copyright 2008-09,2011-12 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <errno.h>
#include <libprelude/prelude.h>
#include <libprelude/idmef-message-print.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "auparse.h"
#include "prelude-config.h"

#define CONFIG_FILE "/etc/audisp/audisp-prelude.conf"
#define ANALYZER_MODEL "auditd"
#define ANALYZER_CLASS "HIDS"
#define ANALYZER_MANUFACTURER "Red Hat, http://people.redhat.com/sgrubb/audit/"
#define PRELUDE_FAIL_CHECK  if (ret < 0) goto err;

typedef enum { AS_LOGIN, AS_MAX_LOGIN_FAIL, AS_MAX_LOGIN_SESS, AS_ABEND,
	AS_PROM, AS_MAC_STAT, AS_LOGIN_LOCATION, AS_LOGIN_TIME, AS_MAC,
	AS_AUTH, AS_WATCHED_LOGIN, AS_WATCHED_FILE, AS_WATCHED_EXEC, AS_MK_EXE,
	AS_MMAP0, AS_WATCHED_SYSCALL, AS_TTY, AS_TOTAL } as_description_t;
const char *assessment_description[AS_TOTAL] = {
 "A user has attempted to login",
 "The maximum allowed login failures for this account has been reached. This could be an attempt to gain access to the account by someone other than the real account holder.",
 "The maximum allowed concurrent logins for this account has been reached.",
 "An application terminated abnormally. An attacker may be trying to exploit a weakness in the program.",
 "A program has opened or closed a promiscuous socket. If this is not expected, it could be an attacker trying to sniff traffic.",
 "A program has changed SE Linux policy enforcement. If this is not expected, it could be an attempt to subvert the system.",
 "A user attempted to login from a location that is not allowed. This could be an attempt to gain access to the account by someone other than the real account holder.",
 "A user attempted to login during a time that the user should not be logging into the system. This could be an attempt to gain access to the account by someone other than the real account holder.",
 "A program has tried to access something that is not allowed in the MAC policy. This could indicate an attacker trying to exploit a weakness in the program.",
 "A user has attempted to use an authentication mechanism and failed. This could be an attempt to gain privileges that they are not supposed to have.",
 "A user has logged in to an account that is being watched.",
 "A user has attempted to access a file that is being watched.",
 "A user has attempted to execute a program that is being watched.",
 "A user has attempted to create an executable program",
 "A program has attempted mmap a fixed memory page at an address sometimes used as part of a kernel exploit",
 "A user has run a command that issued a watched syscall",
 "A user has typed keystrokes on a terminal"
};
typedef enum { M_NORMAL, M_TEST } output_t;
typedef enum { W_NO, W_FILE, W_EXEC, W_MK_EXE } watched_t;

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static prelude_client_t *client = NULL;
static auparse_state_t *au = NULL;
static prelude_conf_t config;
static output_t mode = M_NORMAL;
static char *myhostname=NULL;

/* Local declarations */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

/*
 * SIGTERM handler
 */
static void term_handler( int sig )
{
        stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler( int sig )
{
        hup = 1;
}

static void reload_config(void)
{
	hup = 0;
}

static int setup_analyzer(idmef_analyzer_t *analyzer)
{
	int ret;
	prelude_string_t *string;

	ret = idmef_analyzer_new_model(analyzer, &string);
	PRELUDE_FAIL_CHECK;
	prelude_string_set_dup(string, ANALYZER_MODEL);

	ret = idmef_analyzer_new_class(analyzer, &string);
	PRELUDE_FAIL_CHECK;
	prelude_string_set_dup(string, ANALYZER_CLASS);

	ret = idmef_analyzer_new_manufacturer(analyzer, &string);
	PRELUDE_FAIL_CHECK;
	prelude_string_set_dup(string, ANALYZER_MANUFACTURER);

	ret = idmef_analyzer_new_version(analyzer, &string);
	PRELUDE_FAIL_CHECK;
	prelude_string_set_dup(string, PACKAGE_VERSION);

	return 0;

 err:
	syslog(LOG_ERR, "%s: IDMEF error: %s.\n",
		prelude_strsource(ret), prelude_strerror(ret));

	return -1;
}

static int init_prelude(int argc, char *argv[])
{
	int ret;
	prelude_client_flags_t flags;

	ret = prelude_thread_init(NULL);
	ret = prelude_init(&argc, argv);
	if (ret < 0) {
		syslog(LOG_ERR, 
			"Unable to initialize the Prelude library: %s.\n",
			prelude_strerror(ret));
		return -1;
	}
	ret = prelude_client_new(&client,
			config.profile ? config.profile : ANALYZER_MODEL);
	if (! client) {
		syslog(LOG_ERR,
			"Unable to create a prelude client object: %s.\n",
			prelude_strerror(ret));
		return -1;
	}
	ret = setup_analyzer(prelude_client_get_analyzer(client));
	if (ret < 0) {
		syslog(LOG_ERR, "Unable to setup analyzer: %s\n",
			prelude_strerror(ret));

		prelude_client_destroy(client,
					PRELUDE_CLIENT_EXIT_STATUS_FAILURE);
		prelude_deinit();
		return -1;
	}
	if (mode == M_NORMAL) {
		flags = prelude_client_get_flags(client);
		flags |= PRELUDE_CLIENT_FLAGS_ASYNC_TIMER;
	} else
		flags = 0; // Debug mode
	ret = prelude_client_set_flags(client, flags);
	if (ret < 0) {
		syslog(LOG_ERR, "Unable to set prelude client flags: %s\n",
			prelude_strerror(ret));

		prelude_client_destroy(client,
					PRELUDE_CLIENT_EXIT_STATUS_FAILURE);
		prelude_deinit();
		return -1;
	}
	ret = prelude_client_start(client);
	if (ret < 0) {
		syslog(LOG_ERR, "Unable to start prelude client: %s\n",
			prelude_strerror(ret));

		prelude_client_destroy(client,
					PRELUDE_CLIENT_EXIT_STATUS_FAILURE);
		prelude_deinit();
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;

	if (argc > 1) {
		if (argc == 2 && strcmp(argv[1], "--test") == 0) {
			mode = M_TEST;
		} else {
			fprintf(stderr, "Usage: audisp-prelude [--test]\n");
			return 1;
		}
	}

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	if (load_config(&config, CONFIG_FILE)) {
		if (mode == M_TEST)
		    puts("audisp-prelude is exiting on config load error");
		return 6;
	}

	/* Initialize the auparse library */
	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
		syslog(LOG_ERR,
		    "audisp-prelude is exiting due to auparse init errors");
		free_config(&config);
		return -1;
	}
	auparse_add_callback(au, handle_event, NULL, NULL);
	if (init_prelude(argc, argv)) {
		if (mode == M_TEST)
			puts("audisp-prelude is exiting due to init_prelude");
		else
			syslog(LOG_ERR,
		    "audisp-prelude is exiting due to init_prelude failure");
		free_config(&config);
		auparse_destroy(au);
		return -1;
	}
#ifdef HAVE_LIBCAP_NG
	// Drop all capabilities
	capng_clear(CAPNG_SELECT_BOTH);
	capng_apply(CAPNG_SELECT_BOTH);
#endif
	if (mode != M_TEST)
		syslog(LOG_INFO, "audisp-prelude is ready for events");
	do {
		fd_set read_mask;
		struct timeval tv;
		int retval = -1;

		/* Load configuration */
		if (hup) {
			reload_config();
		}
		do {
			if (retval == 0 && auparse_feed_has_data(au))
				auparse_feed_age_events(au);
			tv.tv_sec = 4;
			tv.tv_usec = 0;
			FD_ZERO(&read_mask);
			FD_SET(0, &read_mask);
			if (auparse_feed_has_data(au))
				retval= select(1, &read_mask, NULL, NULL, &tv);
			else
				retval= select(1, &read_mask, NULL, NULL, NULL);		} while (retval == -1 && errno == EINTR && !hup && !stop);

		/* Now the event loop */
		if (!stop && !hup && retval > 0) {
			if (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH,
				stdin)){
				auparse_feed(au, tmp, strnlen(tmp,
						MAX_AUDIT_MESSAGE_LENGTH));
			}
		} else if (retval == 0)
			auparse_flush_feed(au);
		if (feof(stdin))
			break;
	} while (stop == 0);

	/* Flush any accumulated events from queue */
	auparse_flush_feed(au);

	if (stop) {
		if (mode == M_TEST)
			puts("audisp-prelude is exiting on stop request");
		else
			syslog(LOG_INFO,
				"audisp-prelude is exiting on stop request");
	} else {
		if (mode == M_TEST)
			puts("audisp-prelude is exiting due to end of file");
		else
			syslog(LOG_INFO,
			"audisp-prelude is exiting due to losing input source");
	}

	/* Cleanup subsystems */
	if (client) 
		prelude_client_destroy(client,
					PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
	prelude_deinit();
	auparse_destroy(au);
	free_config(&config);
	free(myhostname);

	return 0;
}

static void print_test_message(idmef_message_t *idmef)
{
	int ret;
	prelude_io_t *fd;

	ret = prelude_io_new(&fd);
	if ( ret < 0 )
		return;

	prelude_io_set_file_io(fd, stdout);
	idmef_message_print(idmef, fd);

	prelude_io_destroy(fd);
}

static void send_idmef(prelude_client_t *client, idmef_message_t *idmef)
{
	if (mode == M_TEST)
		print_test_message(idmef);
	else
		prelude_client_send_idmef(client, idmef);
}

static int new_alert_common(auparse_state_t *au, idmef_message_t **idmef,
			idmef_alert_t **alert)
{
	int ret;
	idmef_time_t *dtime, *ctime;
	time_t au_time;

        ret = idmef_message_new(idmef);
	PRELUDE_FAIL_CHECK;

	ret = idmef_message_new_alert(*idmef, alert);
	PRELUDE_FAIL_CHECK;

	idmef_alert_set_analyzer(*alert,
			idmef_analyzer_ref(prelude_client_get_analyzer(client)),
			IDMEF_LIST_PREPEND);

	// Put the audit time and message ID in the event
	au_time = auparse_get_time(au);
	ret = idmef_time_new_from_time(&dtime, &au_time);
	PRELUDE_FAIL_CHECK;
	idmef_alert_set_detect_time(*alert, dtime);

	// Set time this was created
	ret = idmef_time_new_from_gettimeofday(&ctime);
	PRELUDE_FAIL_CHECK;
	idmef_alert_set_create_time(*alert, ctime);

	return 0;
 err:
	syslog(LOG_ERR, "%s: IDMEF error: %s.\n",
		prelude_strsource(ret), prelude_strerror(ret));
        idmef_message_destroy(*idmef);
        return -1;
}

static int get_loginuid(auparse_state_t *au)
{
	int uid;
	const char *auid;

	auparse_first_field(au);
	auid = auparse_find_field(au, "auid");
	if (auid) 
		uid = auparse_get_field_int(au);
	else
		uid = -1;
	return uid;
}

static int get_new_gid(auparse_state_t *au)
{
	int gid;
	const char *ngid;

	auparse_first_field(au);
	ngid = auparse_find_field(au, "new_gid");
	if (ngid) 
		gid = auparse_get_field_int(au);
	else
		gid = -1;
	return gid;
}

/*
 * This function seeks to the specified record returning its type on succees
 */
static int goto_record_type(auparse_state_t *au, int type)
{
	int cur_type;

	auparse_first_record(au);
	do {
		cur_type = auparse_get_type(au);
		if (cur_type == type) {
			auparse_first_field(au);
			return type;  // Normal exit
		}
	} while (auparse_next_record(au) > 0);

	return -1;
}

static int get_loginuid_info(auparse_state_t *au, idmef_user_id_t *user_id)
{
	int ret, type, is_num = 0;
	const char *auid;

	type = auparse_get_type(au);
	auparse_first_field(au);
	auid = auparse_find_field(au, "acct");
	if (auid == NULL) {
		is_num = 1;
		goto_record_type(au, type);
		auid = auparse_find_field(au, "sauid");
		if (auid == NULL) {
			goto_record_type(au, type);
			if (type == AUDIT_USER_LOGIN) {
				// login programs write auid at second uid
				auparse_find_field(au, "uid");
				auparse_next_field(au);
				auid = auparse_find_field(au, "uid");
			} else {
				auid = auparse_find_field(au, "auid");
			}
		}
	}
	if (auid) {
		prelude_string_t *str;
		ret = prelude_string_new(&str);
		PRELUDE_FAIL_CHECK;

		if (is_num) {
			int uid = auparse_get_field_int(au);
			idmef_user_id_set_number(user_id, uid);
		} else {
			// This use is OK because its looking up local
			// user names to ship externally.
			struct passwd *pw;
			pw = getpwnam(auid);
			if (pw) 
				idmef_user_id_set_number(user_id, pw->pw_uid);
		}

		auid = auparse_interpret_field(au);
		ret = prelude_string_set_ref(str, auid);
		PRELUDE_FAIL_CHECK;
		idmef_user_id_set_name(user_id, str);
	}
	return 0;

 err:
        return -1;
}

static int get_tty_info(auparse_state_t *au, idmef_user_id_t *user_id)
{
	int ret, type;
	const char *tty;

	type = auparse_get_type(au);
	auparse_first_field(au);
	tty = auparse_find_field(au, "terminal");
	if (tty == NULL) {
		goto_record_type(au, type);
		tty = auparse_find_field(au, "tty");
	}
	if (tty) {
		prelude_string_t *str;

		ret = prelude_string_new(&str);
		PRELUDE_FAIL_CHECK;

		ret = prelude_string_set_ref(str, tty);
		PRELUDE_FAIL_CHECK;
		idmef_user_id_set_tty(user_id, str);
	}
	return 0;
 err:
        return -1;
}

static int is_ipv4(const char *addr)
{
	int i = 0;
	while (addr[i]) {
		if ((addr[i] != '.') && !isdigit(addr[i]))
			return 0;
		i++;
	}
	return 1;
}

static int is_ipv6(const char *addr)
{
	int i = 0;
	while (addr[i]) {
		if ((addr[i] != '.') && addr[i] != ':' && !isdigit(addr[i]))
			return 0;
		i++;
	}
	return 1;
}

static int fill_in_node(idmef_node_t *node, const char *addr)
{
	int ret;
	prelude_string_t *str;

	/* Setup the address string */
	ret = prelude_string_new(&str);
	PRELUDE_FAIL_CHECK;
	ret = prelude_string_set_ref(str, addr);
	PRELUDE_FAIL_CHECK;

	/* Now figure out the kind of address */
	if (is_ipv4(addr)) {
		idmef_address_t *my_addr;
		ret = idmef_address_new(&my_addr);
		PRELUDE_FAIL_CHECK;
		idmef_address_set_category(my_addr,
					IDMEF_ADDRESS_CATEGORY_IPV4_ADDR);
		idmef_address_set_address(my_addr, str);
		idmef_node_set_address(node, my_addr, 0);
	} else if (is_ipv6(addr)){
		idmef_address_t *my_addr;
		ret = idmef_address_new(&my_addr);
		PRELUDE_FAIL_CHECK;
		idmef_address_set_category(my_addr,
					IDMEF_ADDRESS_CATEGORY_IPV6_ADDR);
		idmef_address_set_address(my_addr, str);
		idmef_node_set_address(node, my_addr, 0);
	} else { /* Just a host name */
		idmef_node_set_name(node, str);
	}

	return 0;
 err:
        return -1;
}

static int get_rhost_info(auparse_state_t *au, idmef_source_t *source)
{
	int ret;
	idmef_node_t *node;
	const char *hostname;

	auparse_first_field(au);
	hostname = auparse_find_field(au, "hostname");
	if (hostname) {
		if (strcmp(hostname, "?") == 0) {
			auparse_next_field(au);
			hostname = auparse_get_field_str(au);
		}
	} else { /* Some AVCs have the remote addr */
		auparse_first_field(au);
		hostname = auparse_find_field(au, "laddr");
	}

	if (hostname) {
		ret = idmef_source_new_node(source, &node);
		PRELUDE_FAIL_CHECK;
		idmef_node_set_category(node, IDMEF_NODE_CATEGORY_UNKNOWN);

		ret = fill_in_node(node, hostname);
		PRELUDE_FAIL_CHECK;
	}

	return 0;
 err:
        return -1;
}

static int do_node_common(auparse_state_t *au, idmef_node_t *node)
{
	int ret;
	const char *name;

	auparse_first_field(au);
	name = auparse_find_field(au, "node");
	if (name == NULL) {
		if (myhostname == NULL) {
			char tmp_name[255];
			if (gethostname(tmp_name, sizeof(tmp_name)) == 0)
				myhostname = strdup(tmp_name);
		}
		name = myhostname;
		idmef_node_set_category(node, IDMEF_NODE_CATEGORY_HOSTS);
	} else
		idmef_node_set_category(node, IDMEF_NODE_CATEGORY_UNKNOWN);

	if (name) {
		ret = fill_in_node(node, name);
		PRELUDE_FAIL_CHECK;
	} else
		goto err;

	return 0;
 err:
        return -1;
}

static int get_node_info(auparse_state_t *au, idmef_source_t *source,
		idmef_target_t *target)
{
	int ret;
	idmef_node_t *node;

	if (source) {
		ret = idmef_source_new_node(source, &node);
		PRELUDE_FAIL_CHECK;

		ret = do_node_common(au, node);
		PRELUDE_FAIL_CHECK;
	}

	if (target) {
		ret = idmef_target_new_node(target, &node);
		PRELUDE_FAIL_CHECK;

		ret = do_node_common(au, node);
		PRELUDE_FAIL_CHECK;
	}

	return 0;
 err:
        return -1;
}

static int get_login_exe_info(auparse_state_t *au, idmef_target_t *target)
{
	int ret, type;
	idmef_process_t *process;
	const char *exe, *pid;

	ret = idmef_target_new_process(target, &process);
	PRELUDE_FAIL_CHECK;

	type = auparse_get_type(au);
	auparse_first_field(au);
	pid = auparse_find_field(au, "pid");
	if (pid) 
		idmef_process_set_pid(process, auparse_get_field_int(au));

	goto_record_type(au, type);
	exe = auparse_find_field(au, "exe");
	if (exe) {
		char *base;
		prelude_string_t *str, *name_str;
		ret = prelude_string_new(&str);
		PRELUDE_FAIL_CHECK;

		exe = auparse_interpret_field(au);
		ret = prelude_string_set_ref(str, exe);
		PRELUDE_FAIL_CHECK;
		idmef_process_set_path(process, str);

		/* Set process name, login events do not have comm fields */
		base = basename(exe);
		ret = prelude_string_new(&name_str);
		PRELUDE_FAIL_CHECK;
		ret = prelude_string_set_dup(name_str, base);
		PRELUDE_FAIL_CHECK;
		idmef_process_set_name(process, name_str);
	}

	return 0;
 err:
        return -1;
}

static int get_target_group_info(auparse_state_t *au, idmef_user_t *tuser)
{
	int ret;
	const char *ngid;

	auparse_first_field(au);
	ngid = auparse_find_field(au, "new_gid");
	if (ngid) {
		int gid;
		idmef_user_id_t *user_id;
		prelude_string_t *str;
		
		ret = idmef_user_new_user_id(tuser, &user_id, 0);	
		PRELUDE_FAIL_CHECK;
		idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_GROUP_PRIVS);

		ret = prelude_string_new(&str);
		PRELUDE_FAIL_CHECK;

		gid = auparse_get_field_int(au);
		if (gid >= 0)
			idmef_user_id_set_number(user_id, gid);

		ngid = auparse_interpret_field(au);
		ret = prelude_string_set_ref(str, ngid);
		PRELUDE_FAIL_CHECK;
		idmef_user_id_set_name(user_id, str);
	}

	return 0;
 err:
        return -1;
}

static int get_comm_info(auparse_state_t *au, idmef_source_t *source,
		idmef_target_t *target)
{
	int ret, type, need_comm = 1;
	idmef_process_t *process;
	const char *exe, *pid;

	if (source)
		ret = idmef_source_new_process(source, &process);
	else if (target)
		ret = idmef_target_new_process(target, &process);
	else
		return -1;
	PRELUDE_FAIL_CHECK;

	type = auparse_get_type(au);
	auparse_first_field(au);
	pid = auparse_find_field(au, "pid");
	if (pid) 
		idmef_process_set_pid(process, auparse_get_field_int(au));

	goto_record_type(au, type);
	auparse_first_field(au);
	exe = auparse_find_field(au, "comm");
	if (exe) {
		prelude_string_t *str;
		ret = prelude_string_new(&str);
		PRELUDE_FAIL_CHECK;

		exe = auparse_interpret_field(au);
		ret = prelude_string_set_ref(str, exe);
		PRELUDE_FAIL_CHECK;
		idmef_process_set_name(process, str);
		need_comm = 0;
	}

	goto_record_type(au, type);
	exe = auparse_find_field(au, "exe");
	if (exe) {
		prelude_string_t *str;
		ret = prelude_string_new(&str);
		PRELUDE_FAIL_CHECK;

		exe = auparse_interpret_field(au);
		ret = prelude_string_set_ref(str, exe);
		PRELUDE_FAIL_CHECK;
		idmef_process_set_path(process, str);

		/* Set the process name if not set already */
		if (need_comm) {
			prelude_string_t *name_str;

			char *base = basename(exe);
			ret = prelude_string_new(&name_str);
			PRELUDE_FAIL_CHECK;
			ret = prelude_string_set_dup(name_str, base);
			idmef_process_set_name(process, name_str);
		}
	}

	return 0;
 err:
        return -1;
}

/*
 * Fill in a file record for idmef. Note that we always get the
 * full path name unless we have an AVC.
 */
static int get_file_info(auparse_state_t *au, idmef_target_t *target, int full)
{
	int ret;
	idmef_file_t *file;
	const char *name;
	char path[PATH_MAX+1];

	ret = idmef_target_new_file(target, &file, 0);
	PRELUDE_FAIL_CHECK;

	*path = 0;
	if (full) {
		const char *cwd;
		auparse_first_field(au);
		cwd = auparse_find_field(au, "cwd");
		if (cwd) {
			if ((cwd = auparse_interpret_field(au)))
				strcat(path, cwd);
		}
		// Loop across all PATH records in the event
		goto_record_type(au, AUDIT_PATH);
		name = NULL;
		do {	// Make sure that we have an actual file record
			if (auparse_find_field(au, "mode")) {
				int m = auparse_get_field_int(au);
				if (S_ISREG(m)) {
					// Now back up and get file name
					auparse_first_field(au);
					name = auparse_find_field(au, "name");
					break;
				}
			}
		} while (auparse_next_record(au) > 0 &&
				auparse_get_type(au) == AUDIT_PATH);
	} else {
		// SE Linux AVC
		int type = auparse_get_type(au);
		auparse_first_field(au);
		name = auparse_find_field(au, "path");
		if (name == NULL) {
			goto_record_type(au, type);
			name = auparse_find_field(au, "name");
		}
	}
	if (name)
		name = auparse_interpret_field(au); 
	if (name) {
		if (name[0] == '/')
			strcpy(path, name);
		else
			strcat(path, name);
	}
	if (path[0] != 0) {
		prelude_string_t *str;
		ret = prelude_string_new(&str);
		PRELUDE_FAIL_CHECK;

		ret = prelude_string_set_dup(str, path);
		PRELUDE_FAIL_CHECK;
		if (path[0] == '/') {
			char *base;
			prelude_string_t *name_str;

			idmef_file_set_path(file, str);
			base = basename(path);
			if (base[0] == 0)
				base = "/";
			ret = prelude_string_new(&name_str);
			PRELUDE_FAIL_CHECK;
			ret = prelude_string_set_dup(name_str, base);
			PRELUDE_FAIL_CHECK;
			idmef_file_set_name(file, name_str);
		} else
			idmef_file_set_name(file, str);
	}
	idmef_file_set_category(file, IDMEF_FILE_CATEGORY_CURRENT);

	return 0;
 err:
        return -1;
}

static int add_additional_data(idmef_alert_t *alert, const char *title,
		const char *text)
{
	int ret;
	idmef_additional_data_t *data;
	prelude_string_t *str;

        ret = idmef_alert_new_additional_data(alert, &data, IDMEF_LIST_APPEND);
	PRELUDE_FAIL_CHECK;

	ret = idmef_additional_data_new_meaning(data, &str);
	PRELUDE_FAIL_CHECK;

	prelude_string_set_dup(str, title);
	idmef_additional_data_set_type(data, IDMEF_ADDITIONAL_DATA_TYPE_STRING);
       	idmef_additional_data_set_string_ref(data, text);
	return 0;
 err:
        return -1;
}

static int add_serial_number_data(auparse_state_t *au, idmef_alert_t *alert)
{
	int ret;
	idmef_additional_data_t *data;
	prelude_string_t *str;
	unsigned long serial;
	char eid[24];

	serial = auparse_get_serial(au);
	snprintf(eid, sizeof(eid), "%lu", serial); 

        ret = idmef_alert_new_additional_data(alert, &data, IDMEF_LIST_APPEND);
	PRELUDE_FAIL_CHECK;

	ret = idmef_additional_data_new_meaning(data, &str);
	PRELUDE_FAIL_CHECK;

	prelude_string_set_dup(str, "Audit event serial #");
	idmef_additional_data_set_type(data, IDMEF_ADDITIONAL_DATA_TYPE_STRING);
       	idmef_additional_data_set_string_dup(data, eid);
	return 0;
 err:
        return -1;
}

static int add_exit_data(auparse_state_t *au, idmef_alert_t *alert)
{
	const char *e_ptr;

	if (goto_record_type(au, AUDIT_SYSCALL) == -1)
		goto err;
	e_ptr = auparse_find_field(au, "exit");
	if (e_ptr) {
		int ret;
		idmef_additional_data_t *data;
		prelude_string_t *str;
		char exit_code[80];

		snprintf(exit_code, sizeof(exit_code), "%d (%s)", 
			auparse_get_field_int(au),
			auparse_interpret_field(au)); 

	        ret = idmef_alert_new_additional_data(alert,
					&data, IDMEF_LIST_APPEND);
		PRELUDE_FAIL_CHECK;

		ret = idmef_additional_data_new_meaning(data, &str);
		PRELUDE_FAIL_CHECK;

		prelude_string_set_dup(str, "Audit syscall exit code:");
		idmef_additional_data_set_type(data,
					IDMEF_ADDITIONAL_DATA_TYPE_STRING);
	       	idmef_additional_data_set_string_dup(data, exit_code);
	}
	return 0;
 err:
        return -1;
}

static int add_execve_data(auparse_state_t *au, idmef_alert_t *alert)
{
	int ret, i, len = 0;
	idmef_additional_data_t *data;
	prelude_string_t *str;
	const char *msgptr;
	char msg[256], var[16];

	if (goto_record_type(au, AUDIT_EXECVE) != AUDIT_EXECVE)
		return 0;

	msg[0] = 0;
	for (i=0; i<8; i++) {
		snprintf(var, sizeof(var), "a%d", i);
		msgptr = auparse_find_field(au, var);
		if (msgptr) {
			char *ptr;
			int len2;
			len2 = asprintf(&ptr, "%s=%s ", var,
					auparse_interpret_field(au));
			if (len2 < 0) {
				ptr = NULL;
			} else if (len2 > 0 && (len2 + len + 1) < sizeof(msg)) {
				strcat(msg, ptr);
				len += len2;
			}
			free(ptr);
		} else
			break;
	}

        ret = idmef_alert_new_additional_data(alert, &data, IDMEF_LIST_APPEND);
	PRELUDE_FAIL_CHECK;

	ret = idmef_additional_data_new_meaning(data, &str);
	PRELUDE_FAIL_CHECK;

	prelude_string_set_dup(str, "Execve args");
	idmef_additional_data_set_type(data, IDMEF_ADDITIONAL_DATA_TYPE_STRING);
       	idmef_additional_data_set_string_dup(data, msg);
	return 0;
 err:
        return -1;
}

static int set_classification(idmef_alert_t *alert, const char *text)
{
	int ret;
	idmef_classification_t *classification;
	prelude_string_t *str;

	ret = idmef_alert_new_classification(alert, &classification);
	PRELUDE_FAIL_CHECK;
	ret = prelude_string_new(&str);
	PRELUDE_FAIL_CHECK;
	ret = prelude_string_set_ref(str, text);
	PRELUDE_FAIL_CHECK;
	idmef_classification_set_text(classification, str);

	return 0;
 err:
        return -1;
}

static int do_assessment(idmef_alert_t *alert, auparse_state_t *au,
		idmef_impact_severity_t severity, idmef_impact_type_t type,
		const char *descr)
{
	int ret;
	idmef_assessment_t *assessment;
	idmef_impact_t *impact;
	idmef_impact_completion_t completion = IDMEF_IMPACT_COMPLETION_ERROR;
	const char *result;

	auparse_first_record(au);
	result = auparse_find_field(au, "res");
	if (result == NULL) {
		auparse_first_record(au);
		result = auparse_find_field(au, "success");
	} 
	if (result) {
		if (strcmp(result, "yes") == 0)
			completion = IDMEF_IMPACT_COMPLETION_SUCCEEDED;
		else if (strcmp(result, "success") == 0)
			completion = IDMEF_IMPACT_COMPLETION_SUCCEEDED;
		else
			completion = IDMEF_IMPACT_COMPLETION_FAILED;
	}

	// Adjust the rating on AVC's based on if they succeeded or not
	if (goto_record_type(au, AUDIT_AVC) == AUDIT_AVC) {
		if (completion == IDMEF_IMPACT_COMPLETION_FAILED)
			severity = IDMEF_IMPACT_SEVERITY_LOW;
	} else if (goto_record_type(au, AUDIT_USER_AVC) == AUDIT_USER_AVC) {
		if (completion == IDMEF_IMPACT_COMPLETION_FAILED)
			severity = IDMEF_IMPACT_SEVERITY_LOW;
	}
	// If this is a segfault, they failed
	if (goto_record_type(au, AUDIT_ANOM_ABEND) == AUDIT_ANOM_ABEND) 
		completion = IDMEF_IMPACT_COMPLETION_FAILED;

	ret = idmef_alert_new_assessment(alert, &assessment);
	PRELUDE_FAIL_CHECK;
	ret = idmef_assessment_new_impact(assessment, &impact);
	PRELUDE_FAIL_CHECK;
	idmef_impact_set_severity(impact, severity);
	idmef_impact_set_type(impact, type);
	if (descr) {
		prelude_string_t *str;
		ret = idmef_impact_new_description(impact, &str);
		PRELUDE_FAIL_CHECK;
		ret = prelude_string_set_ref(str, descr);
		PRELUDE_FAIL_CHECK;
	}

	// FIXME: I think this is wrong. sb a way to express indeterminate
	if (completion != IDMEF_IMPACT_COMPLETION_ERROR)
		idmef_impact_set_completion(impact, completion);

	return 0;
 err:
        return -1;
}

/*
 * This is for login related alerts
 */
static int login_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert, const char *msg,
		idmef_impact_severity_t severity, as_description_t num)
{
	int ret;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser, *tuser;
	idmef_user_id_t *user_id;
	idmef_impact_type_t impact;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;
	
	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_UNKNOWN);

	ret = get_rhost_info(au, source);
	PRELUDE_FAIL_CHECK;

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;
	ret = idmef_target_new_user(target, &tuser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(tuser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(tuser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_TARGET_USER);

	auparse_first_record(au);
	ret = get_loginuid_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_tty_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_login_exe_info(au, target);
	PRELUDE_FAIL_CHECK;

	ret = get_node_info(au, NULL, target);
	PRELUDE_FAIL_CHECK;
  
	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	ret = set_classification(alert, msg);
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	if (get_loginuid(au) == 0)
		impact = IDMEF_IMPACT_TYPE_ADMIN;
	else
		impact = IDMEF_IMPACT_TYPE_USER;
	ret = do_assessment(alert, au, severity, impact,
				assessment_description[num]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "login_alert: IDMEF error: %s.\n", 
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is for SE Linux AVC related alerts
 */
static int avc_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert)
{
	int ret, type;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser;
	idmef_user_id_t *user_id;
	idmef_impact_type_t impact_type = IDMEF_IMPACT_TYPE_OTHER;
	const char *seperm = NULL;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;
	
	if ((type = goto_record_type(au, AUDIT_SYSCALL)) == AUDIT_SYSCALL ||
	    (type = goto_record_type(au, AUDIT_USER_AVC)) == AUDIT_USER_AVC) {
		ret = idmef_source_new_user(source, &suser);
		PRELUDE_FAIL_CHECK;
		idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
		ret = idmef_user_new_user_id(suser, &user_id, 0);	
		PRELUDE_FAIL_CHECK;
		idmef_user_id_set_type(user_id,
					IDMEF_USER_ID_TYPE_ORIGINAL_USER);
		ret = get_loginuid_info(au, user_id);
		PRELUDE_FAIL_CHECK;

		ret = get_tty_info(au, user_id);
		PRELUDE_FAIL_CHECK;

		ret = get_comm_info(au, source, NULL);
		PRELUDE_FAIL_CHECK;

		ret = get_rhost_info(au, source);
		PRELUDE_FAIL_CHECK;
	} else if ((type = goto_record_type(au, AUDIT_AVC)) == AUDIT_AVC) {
		ret = get_comm_info(au, source, NULL);
		PRELUDE_FAIL_CHECK;
	}

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;

	auparse_first_record(au);
	ret = get_node_info(au, source, target);
	PRELUDE_FAIL_CHECK;

	type = goto_record_type(au, AUDIT_CWD);
	if (type == AUDIT_CWD) {
		ret = get_file_info(au, target, 1);
		PRELUDE_FAIL_CHECK;
		impact_type = IDMEF_IMPACT_TYPE_FILE;
	} else if ((type = goto_record_type(au, AUDIT_AVC)) == AUDIT_AVC) {
		seperm = auparse_find_field(au, "seperm");
		if (auparse_find_field(au, "path")) {
			ret = get_file_info(au, target, 0);
			impact_type = IDMEF_IMPACT_TYPE_FILE;
		} else {
			goto_record_type(au, AUDIT_AVC);
			if (auparse_find_field(au, "name")) {
				ret = get_file_info(au, target, 0);
				impact_type = IDMEF_IMPACT_TYPE_FILE;
			}
		}
	}

	/* Add AVC info for reference */
	if ((goto_record_type(au, AUDIT_AVC) == AUDIT_AVC) ||
		(goto_record_type(au, AUDIT_USER_AVC) == AUDIT_USER_AVC)) {
		ret = add_additional_data(alert, "AVC Text",
					auparse_get_record_text(au));
		PRELUDE_FAIL_CHECK;
	} 
	
	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Detect mmap 0 here */
	type = AS_MAC;
	if (seperm && strcmp(seperm, "mmap_zero") == 0) { 
		const char *tclass = auparse_find_field(au, "tclass");
		if (tclass && strcmp(tclass, "memprotect"))
			type = AS_MMAP0;
	}

	/* Describe event */
	if (type == AS_MAC) {
		ret = set_classification(alert, "MAC Violation");
		PRELUDE_FAIL_CHECK;

		/* Assess impact */
		ret = do_assessment(alert, au, IDMEF_IMPACT_SEVERITY_MEDIUM,
				impact_type, assessment_description[AS_MAC]);
	} else {
		ret = set_classification(alert, "MMAP Page 0");
		PRELUDE_FAIL_CHECK;

		/* Assess impact */
		ret = do_assessment(alert, au, IDMEF_IMPACT_SEVERITY_HIGH,
				impact_type, assessment_description[AS_MMAP0]);
	}
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "avc_alert: IDMEF error: %s.\n",
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is for Application Abnormal Termination related alerts
 */
static int app_term_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert)
{
	int ret;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser, *tuser;
	idmef_user_id_t *user_id;
	const char *sig;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;
	
	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;
	ret = idmef_target_new_user(target, &tuser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(tuser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(tuser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);

	auparse_first_record(au);
	ret = get_loginuid_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_comm_info(au, NULL, target);
	PRELUDE_FAIL_CHECK;

	ret = get_node_info(au, source, target);
	PRELUDE_FAIL_CHECK;

	auparse_first_record(au);
	sig = auparse_find_field(au, "sig");
	if (sig) {
		sig = auparse_interpret_field(au);
		ret = add_additional_data(alert, "Signal", sig);
		PRELUDE_FAIL_CHECK;
	}

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	ret = set_classification(alert, "App Abnormal Termination");
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	ret = do_assessment(alert, au, IDMEF_IMPACT_SEVERITY_MEDIUM,
			IDMEF_IMPACT_TYPE_OTHER,
			assessment_description[AS_ABEND]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "term_alert: IDMEF error: %s.\n",
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is to alert that something has opened a promiscuous socket
 */
static int promiscuous_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert)
{
	int ret, type, old_prom=-1, new_prom=-1;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser, *tuser;
	idmef_user_id_t *user_id;
	const char *dev;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;
	
	type = goto_record_type(au, AUDIT_SYSCALL);
	if (type == AUDIT_SYSCALL) {
		ret = idmef_source_new_user(source, &suser);
		PRELUDE_FAIL_CHECK;
		idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
		ret = idmef_user_new_user_id(suser, &user_id, 0);	
		PRELUDE_FAIL_CHECK;
		idmef_user_id_set_type(user_id,
					IDMEF_USER_ID_TYPE_ORIGINAL_USER);

		ret = get_loginuid_info(au, user_id);
		PRELUDE_FAIL_CHECK;

		ret = get_tty_info(au, user_id);
		PRELUDE_FAIL_CHECK;

		ret = get_comm_info(au, source, NULL);
		PRELUDE_FAIL_CHECK;
	}
	dev = auparse_find_field(au, "dev");
	if (dev) {
		ret = add_additional_data(alert, "Device", dev);
		PRELUDE_FAIL_CHECK;
	}

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;
	ret = idmef_target_new_user(target, &tuser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(tuser, IDMEF_USER_CATEGORY_OS_DEVICE);

	ret = get_node_info(au, source, target);
	PRELUDE_FAIL_CHECK;

	type = goto_record_type(au, AUDIT_ANOM_PROMISCUOUS);
	if (type == AUDIT_ANOM_PROMISCUOUS) {
		const char *old_val, *new_val;

		auparse_first_field(au);
		new_val = auparse_find_field(au, "prom");
		if (new_val)
			new_prom = auparse_get_field_int(au);
		old_val = auparse_find_field(au, "old_prom");
		if (old_val)
			old_prom = auparse_get_field_int(au);
	}

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	if (new_prom == 256 && old_prom == 0)
		ret = set_classification(alert, "Promiscuous Socket Opened");
	else if (new_prom == 0 && old_prom == 256)
		ret = set_classification(alert, "Promiscuous Socket Closed");
	else
		ret = set_classification(alert, "Promiscuous Socket Changed");
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	ret = do_assessment(alert, au, IDMEF_IMPACT_SEVERITY_INFO,
			IDMEF_IMPACT_TYPE_RECON,
			assessment_description[AS_PROM]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "promiscuous_alert: IDMEF error: %s.\n",
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is to alert that something has changed the selinux enforcement
 */
static int mac_status_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert)
{
	int ret, type, old_enforce=-1, new_enforce=-1;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser, *tuser;
	idmef_user_id_t *user_id;
	idmef_impact_severity_t severity;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;
	
	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(suser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);

	type = goto_record_type(au, AUDIT_SYSCALL);
	if (type == AUDIT_SYSCALL) {
		ret = get_loginuid_info(au, user_id);
		PRELUDE_FAIL_CHECK;

		ret = get_tty_info(au, user_id);
		PRELUDE_FAIL_CHECK;

		ret = get_comm_info(au, source, NULL);
		PRELUDE_FAIL_CHECK;
	}

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;
	ret = idmef_target_new_user(target, &tuser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(tuser, IDMEF_USER_CATEGORY_OS_DEVICE);

	ret = get_node_info(au, source, target);
	PRELUDE_FAIL_CHECK;

	type = goto_record_type(au, AUDIT_MAC_STATUS);
	if (type == AUDIT_MAC_STATUS) {
		const char *old_val, *new_val;

		auparse_first_field(au);
		new_val = auparse_find_field(au, "enforcing");
		if (new_val)
			new_enforce = auparse_get_field_int(au);
		old_val = auparse_find_field(au, "old_enforcing");
		if (old_val)
			old_enforce = auparse_get_field_int(au);
	}

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	if (new_enforce == 1 && old_enforce == 0) {
		ret = set_classification(alert, "SE Linux Enforcement Enabled");
		severity = IDMEF_IMPACT_SEVERITY_LOW;
	} else if (new_enforce == 0 && old_enforce == 1) {
		ret = set_classification(alert,"SE Linux Enforcement Disabled");
		severity = IDMEF_IMPACT_SEVERITY_HIGH;
	} else {
		ret = set_classification(alert, "SE Linux Enforcement Changed");
		severity = IDMEF_IMPACT_SEVERITY_LOW;
	}
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	ret = do_assessment(alert, au, severity, IDMEF_IMPACT_TYPE_OTHER,
			assessment_description[AS_MAC_STAT]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "mac_status_alert: IDMEF error: %s.\n",
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is for authentication failure alerts
 */
static int auth_failure_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert, const char *msg,
		idmef_impact_severity_t severity, as_description_t num)
{
	int ret, gid;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser, *tuser;
	idmef_user_id_t *user_id;
	idmef_impact_type_t impact;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;
	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(suser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);

	ret = get_loginuid_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_tty_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_comm_info(au, source, NULL);
	PRELUDE_FAIL_CHECK;

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;
	ret = idmef_target_new_user(target, &tuser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(tuser, IDMEF_USER_CATEGORY_APPLICATION);

	ret = get_target_group_info(au, tuser);
	PRELUDE_FAIL_CHECK;

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	ret = set_classification(alert, msg);
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	gid = get_new_gid(au);
	if (gid == 0 || gid == 10) {	// Root or wheel
		impact = IDMEF_IMPACT_TYPE_ADMIN;
		severity = IDMEF_IMPACT_SEVERITY_MEDIUM;
	} else
		impact = IDMEF_IMPACT_TYPE_USER;
	ret = do_assessment(alert, au, severity, impact,
				assessment_description[num]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "auth_failure_alert: IDMEF error: %s.\n", 
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is for watched syscall related alerts
 */
static int watched_syscall_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert, idmef_impact_severity_t severity)
{
	int ret, rtype;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser;
	idmef_user_id_t *user_id;
	idmef_impact_type_t impact;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;

	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(suser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);
	ret = get_loginuid_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	/* We should only analyze the syscall */
	rtype = goto_record_type(au, AUDIT_SYSCALL);
	ret = get_tty_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_comm_info(au, source, NULL);
	PRELUDE_FAIL_CHECK;

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;

	auparse_first_record(au);
	ret = get_node_info(au, source, target);
	PRELUDE_FAIL_CHECK;

	rtype = goto_record_type(au, AUDIT_CWD);
	if (rtype == AUDIT_CWD) {
		ret = get_file_info(au, target, 1);
		PRELUDE_FAIL_CHECK;
	}
	impact = IDMEF_IMPACT_TYPE_OTHER;

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;
	ret = add_exit_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	ret = set_classification(alert, "Watched Syscall");
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	ret = do_assessment(alert, au, severity, impact,
				assessment_description[AS_WATCHED_SYSCALL]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "watches_syscall_alert: IDMEF error: %s.\n", 
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is for watched file related alerts
 */
static int watched_file_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert, idmef_impact_severity_t severity)
{
	int ret, rtype;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser;
	idmef_user_id_t *user_id;
	idmef_impact_type_t impact;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;

	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(suser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);
	ret = get_loginuid_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_tty_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_comm_info(au, source, NULL);
	PRELUDE_FAIL_CHECK;

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;

	auparse_first_record(au);
	ret = get_node_info(au, source, target);
	PRELUDE_FAIL_CHECK;

	rtype = goto_record_type(au, AUDIT_CWD);
	if (rtype == AUDIT_CWD) {
		ret = get_file_info(au, target, 1);
		PRELUDE_FAIL_CHECK;
	}
	impact = IDMEF_IMPACT_TYPE_FILE;

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	ret = set_classification(alert, "Watched File");
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	ret = do_assessment(alert, au, severity, impact,
				assessment_description[AS_WATCHED_FILE]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "watches_file_alert: IDMEF error: %s.\n", 
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is for watched executable related alerts
 */
static int watched_exec_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert, idmef_impact_severity_t severity)
{
	int ret, rtype;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser;
	idmef_user_id_t *user_id;
	idmef_impact_type_t impact;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;

	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(suser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);
	ret = get_loginuid_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_tty_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_comm_info(au, source, NULL);
	PRELUDE_FAIL_CHECK;

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;

	auparse_first_record(au);
	ret = get_node_info(au, source, target);
	PRELUDE_FAIL_CHECK;

	rtype = goto_record_type(au, AUDIT_CWD);
	if (rtype == AUDIT_CWD) {
		ret = get_file_info(au, target, 1);
		PRELUDE_FAIL_CHECK;
	}

	ret = add_execve_data(au, alert);
	PRELUDE_FAIL_CHECK;

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	ret = set_classification(alert, "Watched Executable");
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	if (get_loginuid(au) == 0)
		impact = IDMEF_IMPACT_TYPE_ADMIN;
	else
		impact = IDMEF_IMPACT_TYPE_USER;
	ret = do_assessment(alert, au, severity, impact,
				assessment_description[AS_WATCHED_EXEC]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "watched_exec_alert: IDMEF error: %s.\n", 
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

/*
 * This is for watching exe's being made related alerts
 */
static int watched_mk_exe_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert, idmef_impact_severity_t severity)
{
	int ret, rtype;
	idmef_source_t *source;
	idmef_target_t *target;
	idmef_user_t *suser;
	idmef_user_id_t *user_id;
	idmef_impact_type_t impact;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;

	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(suser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);
	ret = get_loginuid_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_tty_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_comm_info(au, source, NULL);
	PRELUDE_FAIL_CHECK;

	/* Fill in information about the target of the event */
	ret = idmef_alert_new_target(alert, &target, -1);
	PRELUDE_FAIL_CHECK;

	auparse_first_record(au);
	ret = get_node_info(au, source, target);
	PRELUDE_FAIL_CHECK;

	rtype = goto_record_type(au, AUDIT_CWD);
	if (rtype == AUDIT_CWD) {
		ret = get_file_info(au, target, 1);
		PRELUDE_FAIL_CHECK;
	}
	impact = IDMEF_IMPACT_TYPE_FILE;

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	ret = set_classification(alert, "Executable Created");
	PRELUDE_FAIL_CHECK;

	ret = do_assessment(alert, au, severity, impact,
				assessment_description[AS_MK_EXE]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

        return 0;

 err:
	syslog(LOG_ERR, "watched_mk_exe_alert: IDMEF error: %s.\n", 
		prelude_strerror(ret));
        idmef_message_destroy(idmef);
        return -1;
}

static int account_is_watched(auparse_state_t *au)
{
	const char *auid;

	auparse_first_field(au);
	auid = auparse_find_field(au, "auid");
	if (auid) { // This is for successful logins
		int uid = auparse_get_field_int(au);
		if (ilist_find_num(&config.watched_accounts, uid))
			return 1;
	} else { // Now try failed logins to see if we know who they are
		auparse_first_field(au);
		if ((auid = auparse_find_field(au, "acct"))) {
			struct passwd *pw = getpwnam(auid);
			if (pw && ilist_find_num(
					&config.watched_accounts, pw->pw_uid))
				return 1;
		}
	}
	return 0;
}

static idmef_impact_type_t lookup_itype(const char *kind)
{
	if (strcasecmp(kind, "sys") == 0)
		return IDMEF_IMPACT_TYPE_OTHER;
	if (strcasecmp(kind, "file") == 0)
		return IDMEF_IMPACT_TYPE_FILE;
	if (strcasecmp(kind, "exec") == 0)
		return IDMEF_IMPACT_TYPE_USER;
	if (strcasecmp(kind, "mkexe") == 0)
		return IDMEF_IMPACT_TYPE_OTHER;
	return IDMEF_IMPACT_TYPE_ERROR;
}

static idmef_impact_severity_t lookup_iseverity(const char *severity)
{
	if (strncmp(severity, "inf", 3) == 0)
		return IDMEF_IMPACT_SEVERITY_INFO;
	if (strncmp(severity, "low", 3) == 0)
		return IDMEF_IMPACT_SEVERITY_LOW;
	if (strncmp(severity, "med", 3) == 0)
		return IDMEF_IMPACT_SEVERITY_MEDIUM;
	if (strncmp(severity, "hi", 2) == 0)
		return IDMEF_IMPACT_SEVERITY_HIGH;
	return IDMEF_IMPACT_SEVERITY_ERROR;
}

static void handle_watched_syscalls(auparse_state_t *au,
		idmef_message_t **idmef, idmef_alert_t **alert)
{
	if (config.watched_syscall == E_YES || config.watched_file == E_YES ||
				config.watched_exec == E_YES ||
				config.watched_mk_exe == E_YES) {
		const char *keyptr;
		char *ptr, *kindptr, *ratingptr;
		char key[AUDIT_MAX_KEY_LEN+1];
		idmef_impact_type_t type;
		idmef_impact_severity_t severity;

		/* If no key or key is not for the ids, return */
		auparse_first_field(au);
		keyptr = auparse_find_field(au, "key");
		if (keyptr)
			keyptr = auparse_interpret_field(au);
		while (keyptr) {
			if (strncmp(keyptr, "ids-", 4) == 0)
				break;
			keyptr = auparse_find_field_next(au);
			if (keyptr)
				keyptr = auparse_interpret_field(au);
		}
		if (keyptr == NULL)
			return;

		/* This key is for us, parse it up */
		strncpy(key, keyptr, AUDIT_MAX_KEY_LEN);
		key[AUDIT_MAX_KEY_LEN] = 0;

		ptr = strchr(key, '-'); // There has to be a - because strncmp
		kindptr = ptr + 1;
		ptr = strchr(kindptr, '-');
		if (ptr) {
			*ptr = 0;
			ratingptr = ptr +1;
		} else  // The rules are misconfigured
			return;

		type = lookup_itype(kindptr);
		severity = lookup_iseverity(ratingptr);

		if (type == IDMEF_IMPACT_TYPE_OTHER && 
					strcasecmp(kindptr, "sys") == 0 &&
					config.watched_syscall == E_YES && 
					config.watched_syscall_act == A_IDMEF) {
			if (new_alert_common(au, idmef, alert) >= 0)
				watched_syscall_alert(au, *idmef, *alert,
							severity);
		} else if (type == IDMEF_IMPACT_TYPE_FILE &&
					config.watched_file == E_YES && 
					config.watched_file_act == A_IDMEF) {
			if (new_alert_common(au, idmef, alert) >= 0)
				watched_file_alert(au, *idmef, *alert,
							severity);
		} else if (type == IDMEF_IMPACT_TYPE_USER &&
				config.watched_exec == E_YES &&
				config.watched_exec_act == A_IDMEF) {
			if (new_alert_common(au, idmef, alert) >= 0)
				watched_exec_alert(au, *idmef, *alert,
							severity);
		} else if (type == IDMEF_IMPACT_TYPE_OTHER &&
				strcasecmp(kindptr, "mkexe") == 0 &&
				config.watched_mk_exe == E_YES &&
				config.watched_mk_exe_act == A_IDMEF) {
			if (new_alert_common(au, idmef, alert) >= 0)
				watched_mk_exe_alert(au, *idmef, *alert,
							severity);
		}
	}
}

static int tty_alert(auparse_state_t *au, idmef_message_t *idmef,
		idmef_alert_t *alert)
{
	int ret;

	idmef_source_t *source;
	idmef_user_t *suser;
	idmef_user_id_t *user_id;
	idmef_impact_type_t impact_type;
	idmef_assessment_t *assessment;
	idmef_impact_t *impact;
	idmef_impact_severity_t severity;
	prelude_string_t *str;
	idmef_impact_completion_t completion = IDMEF_IMPACT_COMPLETION_ERROR;

	/* Fill in information about the event's source */
	ret = idmef_alert_new_source(alert, &source, -1);
	PRELUDE_FAIL_CHECK;

	ret = idmef_source_new_user(source, &suser);
	PRELUDE_FAIL_CHECK;
	idmef_user_set_category(suser, IDMEF_USER_CATEGORY_APPLICATION);
	ret = idmef_user_new_user_id(suser, &user_id, 0);	
	PRELUDE_FAIL_CHECK;
	idmef_user_id_set_type(user_id, IDMEF_USER_ID_TYPE_ORIGINAL_USER);
	ret = get_loginuid_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_tty_info(au, user_id);
	PRELUDE_FAIL_CHECK;

	ret = get_comm_info(au, source, NULL);
	PRELUDE_FAIL_CHECK;

	ret = add_execve_data(au, alert);
	PRELUDE_FAIL_CHECK;

	ret = add_serial_number_data(au, alert);
	PRELUDE_FAIL_CHECK;

	/* Describe event */
	ret = set_classification(alert, "Keylogger");
	PRELUDE_FAIL_CHECK;

	/* Assess impact */
	if (get_loginuid(au) == 0)
		impact_type = IDMEF_IMPACT_TYPE_ADMIN;
	else
		impact_type = IDMEF_IMPACT_TYPE_USER;
	completion = IDMEF_IMPACT_COMPLETION_SUCCEEDED;
	severity = IDMEF_IMPACT_SEVERITY_LOW;
	
	ret = idmef_alert_new_assessment(alert, &assessment);
	PRELUDE_FAIL_CHECK;
	ret = idmef_assessment_new_impact(assessment, &impact);
	PRELUDE_FAIL_CHECK;
	idmef_impact_set_severity(impact, severity);
	PRELUDE_FAIL_CHECK;
	idmef_impact_set_type(impact, impact_type);
	PRELUDE_FAIL_CHECK;
	ret = idmef_impact_new_description(impact, &str);
	PRELUDE_FAIL_CHECK;
	ret = prelude_string_set_ref(str, assessment_description[AS_TTY]);
	PRELUDE_FAIL_CHECK;

	send_idmef(client, idmef);
	idmef_message_destroy(idmef);

	return 0;

 err:
	syslog(LOG_ERR, "tty_alert: IDMEF error: %s.\n", 
		prelude_strerror(ret));
	idmef_message_destroy(idmef);
	return -1;
}
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, num=0;
	idmef_message_t *idmef;
	idmef_alert_t *alert;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	// Loop through the records in the event looking for one to process.
	// We use physical record number because we may search around and
	// move the cursor accidentally skipping a record.
	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		switch (type) {
			case AUDIT_AVC:
//			case AUDIT_USER_AVC: ignore USER_AVC for now
				if (config.avcs == E_NO)
					break;
				if (config.avcs_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0)
					avc_alert(au, idmef, alert);
				break;
			case AUDIT_USER_LOGIN:
				// Do normal login alert
				if (config.logins == E_YES &&
					config.logins_act == A_IDMEF) {
				if (new_alert_common(au, &idmef, &alert) >= 0){
					login_alert(au, idmef, alert, "Login",
					IDMEF_IMPACT_SEVERITY_INFO, AS_LOGIN);
				}}
				// Next do watched account alerts
				if (config.watched_acct == E_NO)
					break;
				if (config.watched_acct_act != A_IDMEF)
					break;
				else if (account_is_watched(au)) {
				if (new_alert_common(au, &idmef, &alert) >= 0){
					login_alert(au, idmef, alert,
					"Watched Account Login",
                                        IDMEF_IMPACT_SEVERITY_MEDIUM,
					AS_WATCHED_LOGIN);
				}}
				break;
			case AUDIT_ANOM_LOGIN_FAILURES:
				if (config.login_failure_max == E_NO)
					break;
				if (config.login_failure_max_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0){
					login_alert(au, idmef, alert, 
						"Max Failed Logins",
						IDMEF_IMPACT_SEVERITY_LOW,
						AS_MAX_LOGIN_FAIL);
				}
				break;
			case AUDIT_ANOM_LOGIN_SESSIONS:
				if (config.login_session_max == E_NO)
					break;
				if (config.login_session_max_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0){
					login_alert(au, idmef, alert, 
						"Max Concurrent Sessions",
						IDMEF_IMPACT_SEVERITY_INFO,
						AS_MAX_LOGIN_SESS);
				}
				break;
			case AUDIT_ANOM_LOGIN_LOCATION:
				if (config.login_location == E_NO)
					break;
				if (config.login_location_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0){
					login_alert(au, idmef, alert, 
					"Login From Forbidden Location",
						IDMEF_IMPACT_SEVERITY_MEDIUM,
						AS_LOGIN_LOCATION);
				}
				break;
			case AUDIT_ANOM_LOGIN_TIME:
				if (config.login_time == E_NO)
					break;
				if (config.login_time_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0){
					login_alert(au, idmef, alert, 
						"Login During Forbidden Time",
						IDMEF_IMPACT_SEVERITY_LOW,
						AS_LOGIN_TIME);
				}
				break;
			case AUDIT_ANOM_ABEND:
				if (config.abends == E_NO)
					break;
				if (config.abends_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0)
					app_term_alert(au, idmef, alert);
				break;
			case AUDIT_ANOM_PROMISCUOUS:
				if (config.promiscuous == E_NO)
					break;
				if (config.promiscuous_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0)
					promiscuous_alert(au, idmef, alert);
				break;
			case AUDIT_MAC_STATUS:
				if (config.mac_status == E_NO)
					break;
				if (config.mac_status_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0)
					mac_status_alert(au, idmef, alert);
				break;
			case AUDIT_GRP_AUTH:
				if (config.group_auth == E_NO)
					break;
				if (config.group_auth_act != A_IDMEF)
					break;
				else {
				const char *result;

				// We only care about failures
				auparse_first_field(au);
				result = auparse_find_field(au, "res");
				if (result && strcmp(result, "failed"))
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0){
					auth_failure_alert(au, idmef, alert,
						"Group Authentication Failure",
						IDMEF_IMPACT_SEVERITY_LOW,
						AS_AUTH);
				}}
				break;
			case AUDIT_SYSCALL:
				handle_watched_syscalls(au, &idmef, &alert);
				// The previous call moves the current record
				auparse_goto_record_num(au, num);
				break;
			case AUDIT_TTY:
				if (config.tty == E_NO)
					break;
				if (config.tty_act != A_IDMEF)
					break;
				if (new_alert_common(au, &idmef, &alert) >= 0)
					tty_alert(au, idmef, alert);
				break;
			default:
				break;
		}
		num++;
	}
}

