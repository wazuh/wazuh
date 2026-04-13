#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <errno.h>

#include "logcollector.h"
#include "shared.h"
#include "../wrappers/common.h"

extern int maximum_lines;

static int group_setup(void **state) {
    test_mode = 1;
    maximum_lines = 0;
    return 0;
}

static int group_teardown(void **state) {
    test_mode = 0;
    maximum_lines = 0;
    return 0;
}

int __wrap_can_read() {
    return mock_type(int);
}

int __wrap_w_msg_hash_queues_push(
    const char *str, char *file, unsigned long size, logtarget *targets, char queue_mq) {
    check_expected(str);
    check_expected(file);
    check_expected(size);
    return mock_type(int);
}

/* Mock for recv() used by datagram reader */
ssize_t __wrap_recv(int __fd, void *__buf, size_t __n, int __flags) {
    const char *data = mock_ptr_type(const char *);
    ssize_t retval = mock_type(ssize_t);
    int err = mock_type(int);

    if (retval > 0 && data != NULL) {
        size_t copy_len = (size_t)retval < __n ? (size_t)retval : __n;
        memcpy(__buf, data, copy_len);
    }

    if (retval < 0) {
        errno = err;
    }

    return retval;
}

void test_read_socket_no_data(void **state) {
    logreader lf = { .file = "/tmp/socket.sock", .socket_fd = 7 };
    int rc = -1;

    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, NULL);
    will_return(__wrap_recv, -1);
    will_return(__wrap_recv, EAGAIN);

    expect_string(__wrap__mdebug2, formatted_msg, "Read 0 lines from /tmp/socket.sock");

    assert_null(read_socket(&lf, &rc, 0));
    assert_int_equal(rc, 0);
}

void test_read_socket_single_message(void **state) {
    logreader lf = { .file = "/tmp/socket.sock", .socket_fd = 7 };
    int rc = -1;

    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, "socket event");
    will_return(__wrap_recv, 12);
    will_return(__wrap_recv, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Reading socket message: ''...");
    expect_string(__wrap_w_msg_hash_queues_push, str, "socket event");
    expect_string(__wrap_w_msg_hash_queues_push, file, lf.file);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen("socket event") + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, NULL);
    will_return(__wrap_recv, -1);
    will_return(__wrap_recv, EAGAIN);

    expect_string(__wrap__mdebug2, formatted_msg, "Read 1 lines from /tmp/socket.sock");

    assert_null(read_socket(&lf, &rc, 0));
    assert_int_equal(rc, 0);
}

void test_read_socket_message_with_newline(void **state) {
    logreader lf = { .file = "/tmp/socket.sock", .socket_fd = 7 };
    int rc = -1;

    /* Datagram with trailing newline — should be stripped */
    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, "socket event\n");
    will_return(__wrap_recv, 13);
    will_return(__wrap_recv, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Reading socket message: ''...");
    expect_string(__wrap_w_msg_hash_queues_push, str, "socket event");
    expect_string(__wrap_w_msg_hash_queues_push, file, lf.file);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen("socket event") + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, NULL);
    will_return(__wrap_recv, -1);
    will_return(__wrap_recv, EAGAIN);

    expect_string(__wrap__mdebug2, formatted_msg, "Read 1 lines from /tmp/socket.sock");

    assert_null(read_socket(&lf, &rc, 0));
    assert_int_equal(rc, 0);
}

void test_read_socket_multiple_datagrams(void **state) {
    logreader lf = { .file = "/tmp/socket.sock", .socket_fd = 7 };
    int rc = -1;

    /* First datagram */
    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, "line 1");
    will_return(__wrap_recv, 6);
    will_return(__wrap_recv, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Reading socket message: ''...");
    expect_string(__wrap_w_msg_hash_queues_push, str, "line 1");
    expect_string(__wrap_w_msg_hash_queues_push, file, lf.file);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen("line 1") + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    /* Second datagram */
    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, "line 2");
    will_return(__wrap_recv, 6);
    will_return(__wrap_recv, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Reading socket message: ''...");
    expect_string(__wrap_w_msg_hash_queues_push, str, "line 2");
    expect_string(__wrap_w_msg_hash_queues_push, file, lf.file);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen("line 2") + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    /* No more data */
    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, NULL);
    will_return(__wrap_recv, -1);
    will_return(__wrap_recv, EAGAIN);

    expect_string(__wrap__mdebug2, formatted_msg, "Read 2 lines from /tmp/socket.sock");

    assert_null(read_socket(&lf, &rc, 0));
    assert_int_equal(rc, 0);
}

void test_read_socket_binary_rejected(void **state) {
    logreader lf = { .file = "/tmp/socket.sock", .socket_fd = 7 };
    int rc = -1;
    char payload[] = "a\0b";

    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, payload);
    will_return(__wrap_recv, 3);
    will_return(__wrap_recv, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "Message from socket '/tmp/socket.sock' contains zero-bytes. Dropping.");

    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, NULL);
    will_return(__wrap_recv, -1);
    will_return(__wrap_recv, EAGAIN);

    expect_string(__wrap__mdebug2, formatted_msg, "Read 0 lines from /tmp/socket.sock");

    assert_null(read_socket(&lf, &rc, 0));
    assert_int_equal(rc, 0);
}

void test_read_socket_invalid_utf8_rejected(void **state) {
    logreader lf = { .file = "/tmp/socket.sock", .socket_fd = 7 };
    int rc = -1;
    /* 0xFF is never valid in UTF-8 */
    char payload[] = "hello\xFFworld";

    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, payload);
    will_return(__wrap_recv, (ssize_t)(sizeof(payload) - 1));
    will_return(__wrap_recv, 0);

    expect_string(__wrap__mdebug2, formatted_msg,
                  "Message from socket '/tmp/socket.sock' is not valid UTF-8. Dropping.");

    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, NULL);
    will_return(__wrap_recv, -1);
    will_return(__wrap_recv, EAGAIN);

    expect_string(__wrap__mdebug2, formatted_msg, "Read 0 lines from /tmp/socket.sock");

    assert_null(read_socket(&lf, &rc, 0));
    assert_int_equal(rc, 0);
}

void test_read_socket_maximum_lines(void **state) {
    logreader lf = { .file = "/tmp/socket.sock", .socket_fd = 7 };
    int rc = -1;
    maximum_lines = 1;

    /* First datagram — should be processed */
    will_return(__wrap_can_read, 1);
    will_return(__wrap_recv, "line 1");
    will_return(__wrap_recv, 6);
    will_return(__wrap_recv, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "Reading socket message: ''...");
    expect_string(__wrap_w_msg_hash_queues_push, str, "line 1");
    expect_string(__wrap_w_msg_hash_queues_push, file, lf.file);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen("line 1") + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    /* Loop should stop because maximum_lines == 1 */
    will_return(__wrap_can_read, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Read 1 lines from /tmp/socket.sock");

    assert_null(read_socket(&lf, &rc, 0));
    assert_int_equal(rc, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_socket_no_data),
        cmocka_unit_test(test_read_socket_single_message),
        cmocka_unit_test(test_read_socket_message_with_newline),
        cmocka_unit_test(test_read_socket_multiple_datagrams),
        cmocka_unit_test(test_read_socket_binary_rejected),
        cmocka_unit_test(test_read_socket_invalid_utf8_rejected),
        cmocka_unit_test(test_read_socket_maximum_lines),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
