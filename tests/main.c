#include <stdlib.h>
#include <stdbool.h>

#include "munit/munit.h"
#include "test_suites.h"

#define ARRAY_SIZE(arr) (sizeof(arr)/(sizeof(arr[0])))

MunitSuite other_suites[] = {
    {
        (char*) "pk/",
        pk_tests,
        NULL,
        1,
        MUNIT_SUITE_OPTION_NONE
    },
    {
        (char*) "kek/",
        kek_tests,
        NULL,
        1,
        MUNIT_SUITE_OPTION_NONE
    },
    { NULL, NULL, NULL, 0, MUNIT_SUITE_OPTION_NONE },
};

MunitSuite all_suites = {
  NULL,
  NULL,
  other_suites,
  1,
  MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)])
{
    return munit_suite_main(&all_suites, NULL, argc, argv);
}
