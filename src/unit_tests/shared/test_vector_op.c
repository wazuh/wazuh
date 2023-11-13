#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../headers/shared.h"
#include "../wrappers/common.h"


/* setup/teardown */
static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* tests */
void test_vector_init(void **state)
{
    W_Vector * vector = W_Vector_init(0);
    assert_non_null(vector);
    W_Vector_free(vector);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_vector_init),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
