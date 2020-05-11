#include <stdint.h>
#include "common.h"

int _logfd = -1;

void set_logfd(int logfd)
{
    _logfd = logfd;
}


uint64_t strlen16(char16_t *str)
{
    uint64_t len = 0;
    char16_t *p = str;

    while ( *p++ != L'\0' )
        len++;

    return len;
}

uint64_t strsize16(char16_t *str)
{
    return strlen16(str) * 2;
}
