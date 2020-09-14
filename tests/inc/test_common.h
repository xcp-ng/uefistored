#ifndef __H_COMMON_
#define __H_COMMON_

#include "uefi/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define _DEFAULT_ATTRS                                               \
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |   \
     EFI_VARIABLE_RUNTIME_ACCESS)

#define DEFAULT_GUID { .Data1 = 0xc0defeed }
#define DEFAULT_ATTR                                                 \
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |   \
     EFI_VARIABLE_RUNTIME_ACCESS)

extern int passcount;
extern int failcount;
extern int all_passed;

#define test_printf printf

#define DO_TEST(test)                                                          \
    do {                                                                       \
        pre_test();                                                            \
        test();                                                                \
        post_test();                                                           \
    } while (0)

static inline void _test(const char *file_name, const char *test_name,
                         int lineno, const char *assertion, bool passed)
{
    if (!passed) {
        failcount++;
        test_printf("\n%s:%s:%d: %s: fail\n", file_name, test_name, lineno,
                    assertion);
    } else {
        passcount++;
        test_printf(".");
    }
}

#define test(assertion)                                                         \
        do {                                                                    \
            _test(__FILE__, __func__, __LINE__, #assertion, assertion);         \
            if (!(assertion))                                                   \
                return;                                                         \
        } while( 0 )

static inline void _test_eq_int64(const char *file_name, const char *test_name,
                                  int lineno, const char *val1_str,
                                  const char *val2_str, uint64_t val1,
                                  uint64_t val2)
{
    if (val1 != val2) {
        failcount++;
        test_printf("\n%s:%s:%d: fail: ", file_name, test_name, lineno);
        test_printf(" %s != %s  (0x%02lx != 0x%02lx)\n", val1_str, val2_str,
                    val1, val2);
    } else {
        passcount++;
        test_printf(".");
    }
}

#define test_eq_int64(val1, val2)                                              \
    _test_eq_int64(__FILE__, __func__, __LINE__, #val1, #val2, val1, val2)

EFI_STATUS testutil_query_variable_info(uint32_t Attributes,
                                   uint64_t *MaximumVariableStorageSize,
                                   uint64_t *RemainingVariableStorageSize,
                                   uint64_t *MaximumVariableSize);

EFI_STATUS testutil_set_variable(wchar_t *name, EFI_GUID *guid,
                                 uint32_t attr, size_t datasize, void *data);

EFI_STATUS testutil_get_variable(UTF16 *variable, EFI_GUID *guid,
                                 uint32_t *attrs, size_t *size,
                                 void *data);

#endif //  __H_COMMON_
