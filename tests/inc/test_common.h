#ifndef __H_COMMON_
#define __H_COMMON_

#include "UefiMultiPhase.h"
#include <stdio.h>

extern int passcount;
extern int failcount;
extern int all_passed;

#define DO_TEST(test)                                   \
    do  {                                               \
        printf("\n++++++++  %s  ++++++++\n", #test);           \
        pre_test();                                     \
        test();                                         \
        post_test();                                    \
    }  while ( 0 )

#define test(assertion)                                                 \
    do {                                                                \
        if ( !(assertion) )                                             \
        {                                                               \
            printf("%s:%s:%d: %s: %s\n", __FILE__, __func__, __LINE__, #assertion, "fail");   \
            failcount++;                                                \
        }                                                               \
        else                                                            \
        {                                                               \
            printf("%s:%s:%d: %s: %s\n", __FILE__, __func__, __LINE__, #assertion, "pass");   \
            passcount++;                                                \
        }                                                               \
    } while ( 0 )

#define DEFAULT_ATTR (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS)

#endif //  __H_COMMON_
