#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>

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
        (char*) "xapi/",
        xapi_tests,
        NULL,
        1,
        MUNIT_SUITE_OPTION_NONE
    },
    {
        (char*) "xen_variable_server_tests/",
        xen_variable_server_tests,
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
    int ret;

    /* Require no fork */
    char *newargs[] = { argv[0],  "--no-fork" };

    ret = munit_suite_main(&all_suites, NULL, 2, newargs);

    /* deinitialize everything OpenSSL */

    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    ENGINE_cleanup();
    ERR_free_strings();
    EVP_cleanup();


#if OPENSSL_VERSION_NUMBER < 0x10100000
    ERR_remove_thread_state(NULL);
#endif

    CRYPTO_cleanup_all_ex_data();

    return ret;
}
