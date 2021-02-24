#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "log.h"

#include "munit/munit.h"
#include "test_suites.h"

struct backend *backend = NULL;
const enum loglevel loglevel = LOGLEVEL_ERROR;


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
    {
        (char*) "db/",
        db_tests,
        NULL,
        1,
        MUNIT_SUITE_OPTION_NONE
    },
    {
        (char*) "auth/",
        auth_tests,
        NULL,
        1,
        MUNIT_SUITE_OPTION_NONE
    },
    {
        (char*) "auth_func/",
        auth_func_tests,
        NULL,
        1,
        MUNIT_SUITE_OPTION_NONE
    },
    {
        (char*) "base64/",
        base64_tests,
        NULL,
        1,
        MUNIT_SUITE_OPTION_NONE
    },
    {
        (char*) "xapi/",
        xapi_tests,
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
    /* Require no fork */
    char *newargs[] = { argv[0],  "--no-fork" };

    return munit_suite_main(&all_suites, NULL, 2, newargs);
}
