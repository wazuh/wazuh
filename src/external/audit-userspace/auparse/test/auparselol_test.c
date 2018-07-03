#include "config.h"
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <getopt.h>
#include "libaudit.h"
#include "auparse.h"

/*
 * Tool to exercise the auparse library input and processing capability
 * Based on the code example shown in auparse_feed manual entry
 *
 * Standard test would be
 *	mkdir /tmp/auparse_test
 *	cp /var/log/audit/audit.log /tmp/auparse_test/audit.log
 *	sed -f auparse_patch.sed /tmp/auparse_test/audit.log | sort > /tmp/auparse_test/auparse.raw
 *	auparselol_test --check -f /tmp/auparse_test/audit.log | sort > /tmp/auparse_test/auparse.new
 *	diff /tmp/auparse_test/auparse.raw /tmp/auparse_test/auparse.new
 * and the ouput of the diff should be zero or explainable (and hence expand the auparse_patch.sed file)
 *
 */

/*
 * Flags bitset
 */
unsigned flags = 0x0;

#define	F_VERBOSE	0x00000001
#define	F_CHECK		0x00000002
#define	F_USESTDIN	0x00000004

/*
 * Print a null terminated string, escaping chararters from the given set
 */
void print_escape(FILE * fd, char *str, const char *escape)
{
    register char *s = str;
    int ch;

    while ((ch = (int) *s++)) {
        if (strrchr(escape, ch))
            fputc('\\', fd);
        fputc(ch, fd);
    }
}

/*
 * auparse_callback - callback routine to be executed once a complete event is composed
 */
void
auparse_callback(auparse_state_t * au, auparse_cb_event_t cb_event_type,
                 void *user_data)
{
    int *event_cnt = (int *) user_data;

    if (cb_event_type == AUPARSE_CB_EVENT_READY) {
        if (auparse_first_record(au) <= 0)
            return;             /* If no first record, then no event ! */

        if (!(flags & F_CHECK))
            printf("event=%d records=%d\n", *event_cnt,
                   auparse_get_num_records(au));
        do {
            const au_event_t *e = auparse_get_timestamp(au);
            if (e == NULL)
                return;         /* If no timestamp, then no event */

            /* If checking, we just emit the raw record again
             */
            if (flags & F_CHECK) {
                if (e->host != NULL)
                    printf("node=%s type=%s msg=audit(%u.%3.3u:%lu):",
                           e->host, auparse_get_type_name(au),
                           (unsigned) e->sec, e->milli, e->serial);
                else
                    printf("type=%s msg=audit(%u.%3.3u:%lu):",
                           auparse_get_type_name(au),
                           (unsigned) e->sec, e->milli, e->serial);
                auparse_first_field(au);        /* Move to first field */
                do {
                    const char *fname = auparse_get_field_name(au);

                    /* We ignore the node and type fields */
                    if (strcmp(fname, "type") == 0
                        || strcmp(fname, "node") == 0)
                        continue;
                    printf(" %s=%s", fname, auparse_get_field_str(au));
                } while (auparse_next_field(au) > 0);
                printf("\n");
                continue;
            }

            printf("fields=%d\t", auparse_get_num_fields(au));
            printf("type=%d (%s) ", auparse_get_type(au),
                   auparse_get_type_name(au));
            printf("event_tid=%u.%3.3u:%lu ",
                   (unsigned) e->sec, e->milli, e->serial);
            if (flags & F_VERBOSE) {
                char *fv, *ifv = NULL;
                auparse_first_field(au);        /* Move to first field */
                do {
                    fv = (char *) auparse_get_field_str(au);
                    ifv = (char *) auparse_interpret_field(au);
                    printf("%s=", auparse_get_field_name(au));
                    print_escape(stdout, fv, "=()");
                    printf(" (");
                    print_escape(stdout, ifv, "=()");
                    printf(") ");
                }
                while (auparse_next_field(au) > 0);
            }
            printf("\n");
        }
        while (auparse_next_record(au) > 0);
        (*event_cnt)++;
    }
}

void usage(void)
{
    fprintf(stderr,
            "usage: auparselol_test [--stdin] [-f file] [--verbose] [--check] [--escape R|T|S|Q]\n");
}

int main(int argc, char **argv)
{
    char *filename = NULL;
    auparse_esc_t em;
    FILE *fd;
#define	BUFSZ	2048
    char buf[BUFSZ];
    size_t len;
    int *event_cnt = NULL;
    auparse_state_t *au;
    int i;
    /* Argument parsing */
    while (1) {
        int option_index = 0;
        int c;
        static struct option long_options[] = {
            { "verbose", no_argument, 0, 'v'},
            { "file", required_argument, 0, 'f'},
            { "stdin", no_argument, 0, 's'},
            { "check", no_argument, 0, 'c'},
            { "escape", required_argument, 0, 'e'},
            { 0, 0, 0, 0}
        };
        c = getopt_long(argc, argv, "cvf:e:s", long_options,
                        &option_index);
        if (c == -1)
            break;
        switch (c) {
        case 'e':              /* escape mode */
            switch (*optarg) {
            case 'R':
            case 'r':
                em = AUPARSE_ESC_RAW;
                break;
            case 'T':
            case 't':
                em = AUPARSE_ESC_TTY;
                break;
            case 'S':
            case 's':
                em = AUPARSE_ESC_SHELL;
                break;
            case 'Q':
            case 'q':
                em = AUPARSE_ESC_SHELL_QUOTE;
                break;
            default:
                fprintf(stderr,
                        "%s: Unknown escape character 0x%2.2X\n",
                        argv[0], *optarg);
                usage();
                return 1;
            }
            auparse_set_escape_mode(NULL, em);
            break;
        case 'c':              /* check */
            flags |= F_CHECK;
            break;
        case 'v':              /* verbose */
            flags |= F_VERBOSE;
            break;
        case 's':              /* stdin */
            flags |= F_USESTDIN;
            break;
        case 'f':              /* file */
            filename = optarg;
            break;
        case '?':
        default:
            fprintf(stderr, "%s: Unknown option 0x%2.2X\n", argv[0], c);
            usage();
            return 1;
        }
    }
    if ((flags & F_USESTDIN) && filename != NULL) {
        fprintf(stderr,
                "%s: --stdin cannot be used with file argument\n",
                argv[0]);
        usage();
        return 1;
    }
    if (!(flags & F_USESTDIN) && filename == NULL) {
        fprintf(stderr,
                "%s: Missing --stdin or -f file argument\n", argv[0]);
        usage();
        return 1;
    }

    if ((event_cnt = malloc(sizeof(int))) == NULL) {
        fprintf(stderr,
                "%s: No memory to allocate %lu bytes\n",
                argv[0], sizeof(int));
        return 1;
    }

    if (flags & F_USESTDIN) {
        fd = stdin;
    } else {
        if ((fd = fopen(filename, "r")) == NULL) {
            fprintf(stderr, "could not open ’%s’, %s\n",
                    filename, strerror(errno));
            (void) free(event_cnt);
            return 1;
        }
    }

    au = auparse_init(AUSOURCE_FEED, NULL);
    *event_cnt = 1;
    auparse_add_callback(au, auparse_callback, event_cnt, free);
    i = 0;
    while ((len = fread(buf, 1, sizeof(buf), fd))) {

        auparse_feed(au, buf, len);
        i++;
    }
    auparse_flush_feed(au);
    auparse_destroy(au);        /* this also free's event_cnt */
    if (!(flags & F_USESTDIN))
        fclose(fd);
    return 0;
}
