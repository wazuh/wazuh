/* skeleton.c --
 * 
 * This is a sample dispatcher program that you can customize to create your
 * own audit event handler. It will be started by auditd via the dispatcher
 * option in /etc/audit/auditd.conf. It is much preferred that you create
 * and audispd plugin for real time analytical needs. But this is here just
 * in case you really prefer to get things straight from auditd.
 *
 * NOTE: The dispatcher interface will be going away at some point.
 *
 * This program can be built as follows:
 *
 * gcc skeleton.c -o skeleton -laudit
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <locale.h>
#include "libaudit.h"


// Local data
static volatile int signaled = 0;
static int pipe_fd;
static const char *pgm = "skeleton";

// Local functions
static int event_loop(void);

// SIGTERM handler
static void term_handler( int sig )
{
	signaled = 1;
}


/*
 * main is started by auditd. See dispatcher in auditd.conf
 */
int main(int argc, char *argv[])
{
	struct sigaction sa;

	setlocale (LC_ALL, "");
	openlog(pgm, LOG_PID, LOG_DAEMON);
	syslog(LOG_NOTICE, "starting...");

	// register sighandlers
	sa.sa_flags = 0 ;
	sa.sa_handler = term_handler;
	sigemptyset( &sa.sa_mask ) ;
	sigaction( SIGTERM, &sa, NULL );
	sa.sa_handler = term_handler;
	sigemptyset( &sa.sa_mask ) ;
	sigaction( SIGCHLD, &sa, NULL );
	sa.sa_handler = SIG_IGN;
	sigaction( SIGHUP, &sa, NULL );
	(void)chdir("/");

	// change over to pipe_fd
	pipe_fd = dup(0);
	close(0);
	open("/dev/null", O_RDONLY);
	fcntl(pipe_fd, F_SETFD, FD_CLOEXEC);

	// Start the program
	return event_loop();
}

static int event_loop(void)
{
	void *data;
	struct iovec vec[2];
	struct audit_dispatcher_header hdr;

	// allocate data structures
	data = malloc(MAX_AUDIT_MESSAGE_LENGTH);
	if (data == NULL) {
		syslog(LOG_ERR, "Cannot allocate buffer");
		return 1;
	}
	memset(data, 0, MAX_AUDIT_MESSAGE_LENGTH);
	memset(&hdr, 0, sizeof(hdr));

	do {
		int rc;
		struct timeval tv;
		fd_set fd;

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&fd);
		FD_SET(pipe_fd, &fd);
		rc = select(pipe_fd+1, &fd, NULL, NULL, &tv);
		if (rc == 0) 
			continue;
		 else if (rc == -1)
			break;

		/* Get header first. it is fixed size */
		vec[0].iov_base = (void*)&hdr;
		vec[0].iov_len = sizeof(hdr);
		do {
			rc = readv(fd, &vec[0], 1);
		} while (rc < 0 && errno == EINTR);

		if (rc > 0) {
	        	// Next payload 
			vec[1].iov_base = data;
			vec[1].iov_len = hdr.size; 
			do {
				rc = readv(fd, &vec[1], 1);
			} while (rc < 0 && errno == EINTR);
		}
		if (rc <= 0) {
			syslog(LOG_ERR, "rc == %d(%s)", rc, strerror(errno));
			continue;
		}

		// Handle events here. Just for illustration, we print
		// to syslog, but you will want to do something else.
		syslog(LOG_NOTICE,"type=%d, payload size=%d", 
			hdr.type, hdr.size);
		syslog(LOG_NOTICE,"data=\"%.*s\"", hdr.size,
			(char *)data);

	} while(!signaled);

	return 0;
}

