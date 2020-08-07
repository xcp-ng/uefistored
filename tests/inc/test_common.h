#ifndef __H_COMMON_
#define __H_COMMON_

#include "uefi/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static const EFI_GUID DEFAULT_GUID = { .Data1 = 0xc0defeed };
static const uint32_t DEFAULT_ATTRS = 0xdeadbeef;

#define DISABLE_STDIO 1

extern int passcount;
extern int failcount;
extern int all_passed;

#if DISABLE_STDIO
static int old_stdout;
static int old_stderr;
static bool redirected;

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

#else

#define test_printf printf
#define redirect_init() do { } while (0)
#define redirect_deinit() do { } while (0)

#endif

#define DO_TEST(test)                                   \
    do  {                                               \
        redirect_init();                                \
        pre_test();                                     \
        test();                                         \
        post_test();                                    \
        redirect_deinit();                              \
    }  while ( 0 )

static inline void  _test(const char *file_name, const char *test_name,
                          int lineno, const char *assertion, bool passed)
{
    if ( !passed )
    {
        failcount++;
        test_printf("\n%s:%s:%d: %s: fail\n", file_name, test_name, lineno, assertion);
    }
    else
    {
        passcount++;
        test_printf(".");
    }
}

#define test(assertion)	\
	_test(__FILE__, __func__, __LINE__, #assertion, assertion)

static inline void  _test_eq_int64(const char *file_name, const char *test_name,
                                   int lineno,
                                   const char *val1_str, const char *val2_str,
                                   uint64_t val1, uint64_t val2)
{
    if ( val1 != val2 )
    {
        failcount++;
        test_printf("\n%s:%s:%d: fail: ", file_name, test_name, lineno);
        test_printf(" %s != %s  (0x%02lx != 0x%02lx)\n", val1_str, val2_str, val1, val2);
    }
    else
    {
        passcount++;
        test_printf(".");
    }
}

#define test_eq_int64(val1, val2)	\
	_test_eq_int64(__FILE__, __func__, __LINE__, #val1, #val2, val1, val2)

#define DEFAULT_ATTR (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS)

#endif //  __H_COMMON_
