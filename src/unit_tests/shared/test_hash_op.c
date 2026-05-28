#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "shared.h"

int setup_queue(void **state) {
    OSHash *hash = OSHash_Create();
    *state = hash;
    return 0;
}

int teardown_queue(void **state) {
    OSHash *hash = *state;
    OSHash_Free(hash);
    return 0;
}

/* tests */

/* oshash_add */

void test_oshash_add_ok(void **state)
{
    OSHash *hash = *state;
    char *key = "key";
    char *value = "value";
    int ret;
    ret = OSHash_Add(hash, key, value);
    assert_int_equal(ret, 2);
}

void test_oshash_add_same_elem(void **state)
{
    OSHash *hash = *state;
    char *key = "key";
    char *value = "value";
    int ret;
    ret = OSHash_Add(hash, key, value);
    ret = OSHash_Add(hash, key, value);
    assert_int_equal(ret, 1);
}

int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_oshash_add_ok, setup_queue, teardown_queue),
        cmocka_unit_test_setup_teardown(test_oshash_add_same_elem, setup_queue, teardown_queue)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}