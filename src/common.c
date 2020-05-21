#include <stdint.h>
#include "common.h"

bool variable_is_empty(variable_t *v1)
{
    if ( !v1 )
    {
        ERROR("%s: null ptr, reporting it as empty...\n", __func__);
       return true;
    }

    /* tWO ZERO BYTES IS END OF STRING IN ucs-2 /CHAR16 */
    return v1->name[0] == 0 && v1->name[1] == 0;
}


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

void uc2_ascii_safe(void *uc2, size_t uc2_len, char *ascii, size_t len)
{
    int i;
    int j = 0;

    for (i=0; i<uc2_len && j<(len-1); i++)
    {
        char c = *((char*)(uc2+i));
        if ( c != '\0' )
            ascii[j++] = c;
    }

    ascii[j++] = '\0';
}

void uc2_ascii(void *uc2, char *ascii, size_t len)
{
    int i,j;

    for ( i=0; i<512; i++ )
    {
        j = i + 1;
        
        if ( ((char*)uc2)[i] == 0 && ((char*)uc2)[j] == 0 )
            break;
    }

    uc2_ascii_safe(uc2, (size_t)i, ascii, len);
}

/**
 * dprint_variable -  Debug print a variable
 *
 * WARNING: this only prints ASCII characters correctly.
 * Any char code above 255 will be displayed incorrectly.
 */

void dprint_variable(variable_t *var)
{
    char buf[MAX_VARNAME_SZ] = {0};

    uc2_ascii_safe(var->name, var->namesz, buf, MAX_VARNAME_SZ);
    DEBUG("Variable(%s)\n", buf);
}
