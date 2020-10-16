#include <stdlib.h>
#include <stdbool.h>

#include "munit/munit.h"
#include "test_pk.h"

#define ARRAY_SIZE(arr) (sizeof(arr)/(sizeof(arr[0])))

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)])
{
    int i;
    bool passed = true;
    const MunitSuite suites[] = {
        test_suite_pk,
    };

    for (i=0; i<ARRAY_SIZE(suites); i++) {
        if (munit_suite_main(&suites[i], NULL, argc, argv) != EXIT_SUCCESS)
            passed = false;
    }

    return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
