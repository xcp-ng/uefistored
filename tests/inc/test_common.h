#ifndef __H_COMMON_
#define __H_COMMON_

#include "UefiMultiPhase.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static char assertion[128];
extern int passcount;
extern int failcount;
extern int all_passed;
static int old_fail_count;
static int old_stdout;
static int old_stderr;

static inline void redirect_init(void)
{
    int new_stdout, new_stderr;

    fflush(stdout);
    old_stdout = dup(1);
    old_stderr = dup(2);

    new_stdout = open("/dev/null", O_WRONLY);
    dup2(new_stdout, 1);
    close(new_stdout);

    new_stderr = open("/dev/null", O_WRONLY);
    dup2(new_stderr, 2);
    close(new_stderr);
}

static inline void redirect_deinit(void)
{
    fflush(stdout);
    dup2(old_stdout, 1);
    close(old_stdout);

    fflush(stderr);
    dup2(old_stderr, 2);
    close(old_stderr);
}

static inline void pre_pre_test(void)
{
    old_fail_count = failcount;
}

static inline void post_post_test(const char *test_name)
{
    if ( old_fail_count != failcount )
        printf("%s:%s:%d: %s: %s\n", __FILE__, test_name, __LINE__, assertion, "fail");

    memset(assertion, 0, strlen(assertion));
}

#define DO_TEST(test)                                   \
    do  {                                               \
        pre_pre_test();                                 \
        redirect_init();                                \
        pre_test();                                     \
        test();                                         \
        post_test();                                    \
        redirect_deinit();                              \
        post_post_test(#test);                               \
    }  while ( 0 )

#define test(_assertion)                                                \
    do {                                                                \
        if ( !(_assertion) )                                            \
        {                                                               \
            strcpy(assertion, #_assertion);                             \
            failcount++;                                                \
            return;                                                     \
        }                                                               \
        else                                                            \
        {                                                               \
            printf(".");                                                \
            passcount++;                                                \
        }                                                               \
    } while ( 0 )

#define DEFAULT_ATTR (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS)

#endif //  __H_COMMON_
