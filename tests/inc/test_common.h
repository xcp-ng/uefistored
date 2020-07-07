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
static bool redirected;
int test_lineno;

static inline void redirect_init(void)
{
    int new_stdout, new_stderr;

    if ( redirected )
        return;

    fflush(stdout);
    old_stdout = dup(1);
    old_stderr = dup(2);

    new_stdout = open("/dev/null", O_WRONLY);
    dup2(new_stdout, 1);
    close(new_stdout);

    new_stderr = open("/dev/null", O_WRONLY);
    dup2(new_stderr, 2);
    close(new_stderr);

    redirected = true;
}

static inline void redirect_deinit(void)
{
    if ( !redirected )
        return;

    fflush(stdout);
    dup2(old_stdout, 1);
    close(old_stdout);

    fflush(stderr);
    dup2(old_stderr, 2);
    close(old_stderr);

    redirected = false;
}

#define test_printf(...)            \
    do {                            \
       redirect_deinit();           \
       printf(__VA_ARGS__);         \
       redirect_init();             \
    } while ( 0 )

static inline void pre_pre_test(void)
{
    old_fail_count = failcount;
}

static inline void post_post_test(const char *file_name, const char *test_name)
{
    if ( old_fail_count != failcount )
        printf("%s:%s:%d: %s: %s\n", file_name, test_name, test_lineno, assertion, "fail");

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
        post_post_test(__FILE__, #test);                               \
    }  while ( 0 )

#define _test(_assertion, _lineno)                                                \
    do {                                                                \
        if ( !(_assertion) )                                            \
        {                                                               \
            strcpy(assertion, #_assertion);                             \
            test_lineno = _lineno;                             \
            failcount++;                                                \
            return;                                                     \
        }                                                               \
        else                                                            \
        {                                                               \
            printf(".");                                                \
            passcount++;                                                \
        }                                                               \
    } while ( 0 )

#define test(_assertion)	\
	_test(_assertion, __LINE__)

#define DEFAULT_ATTR (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS)

#endif //  __H_COMMON_
