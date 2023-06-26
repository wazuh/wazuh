#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include "add.h"

 
int __real_add(int a, int b);
int __wrap_add(int a, int b) {
  check_expected(a);
  check_expected(b);
  printf("\n Wrap function \n\n");
  return mock();
}


/* A test case that does nothing and succeeds. */
static void test_add(void **state) {
    (void) state; /* unused */
    int ret;
   
    expect_value(__wrap_add, a, 2);
    expect_value(__wrap_add, b, 3);
    will_return(__wrap_add, 7);

    // expect_function_call(__wrap_add);
    ret = added(2,3);

    assert_int_equal(ret, 5);
}
 
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_add),
    };
 
    return cmocka_run_group_tests(tests, NULL, NULL);
}
