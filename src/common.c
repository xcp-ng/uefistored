#include <stdint.h>

#include "common.h"
#include "log.h"
#include "uefitypes.h"

char strbuf[512] = {0};

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

/**
 * Return the length of a UTF16 string.
 *
 * Arg `str` MUST be null-terminated (2 bytes of zero).
 */
uint64_t strlen16(const UTF16 *str)
{
    uint64_t len = 0;
    uint8_t *p1;
    uint8_t *p2;

    if ( !str )
        return 0;

    p1 = (uint8_t*)str;
    p2 = p1 + 1;

    while ( true )
    {
        /* Somthing is wrong if either pointers are null */
        if ( !p1 || !p2 )
            break;

        /* zero pointers means we have reached the null-terminator */
        if ( !(*p1 || *p2) )
            break;

        /*
         * We are processing two bytes at a time, so jump two bytes and
         * increment the length
         */
        p1 += 2;
        p2 += 2;
        len++;
    }

    return len;
}

/**
 * Returns the size of the string in total bytes.
 *
 * Because this is measuring UTF16 strings, the size will always be
 * double the length.
 *
 * Does NOT include null-terminator.
 */
uint64_t strsize16(const UTF16 *str)
{
    return strlen16(str) * sizeof(UTF16);
}

void uc2_ascii_safe(UTF16 *uc2, size_t uc2_len, char *ascii, size_t len)
{
    int i;

    for (i=0; i<uc2_len && i<len && uc2[i]; i++)
        ascii[i] = (char)uc2[i];

    ascii[i++] = '\0';
}

void uc2_ascii(UTF16 *uc2, char *ascii, size_t len)
{
    uc2_ascii_safe(uc2, strsize16(uc2), ascii, len);
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

/**
 * Returns 0 if a and b are equal, otherwise non-zero.
 */
int strcmp16(const UTF16 *a, const UTF16 *b)
{
    size_t a_sz, b_sz;

    a_sz = strsize16(a);
    b_sz = strsize16(b);

    if ( a_sz != b_sz )
    {
        return -1;
    }

    return memcmp(a, b, min(a_sz, b_sz));
}

/**
 * Copies string `b` to string `a`.
 *
 * Adds null-terminator to `a`.  Won't exceed `n`. 
 */
int strncpy16(UTF16 *a, const UTF16 *b, const size_t n)
{
    uint8_t *p;
    size_t b_sz;

    b_sz = strsize16(b);
    
    if ( b_sz > n )
        return -1;

    memcpy(a, b, b_sz);

    p =  (uint8_t*)a;
    p[b_sz] = 0;
    p[b_sz + 1] = 0;

    return 0;
}

void dprint_data(void *data, size_t datalen)
{
    uint8_t *p = data;
    size_t i;

    DPRINTF("DATA: ");
    for (i=0; i<datalen; i++)
    {
        if (i % 8 == 0)
            DPRINTF("\n%02lx: 0x", i);
        DPRINTF("%02x", p[i]);
    }
    DPRINTF("\n");
}

/* TODO: filter on guid */
variable_t *find_variable(const UTF16 *name, variable_t variables[MAX_VAR_COUNT], size_t n)
{
    variable_t *var;
    size_t i;

    for ( i=0; i<n; i++ )
    {
        var = &variables[i];

        if ( strcmp16((UTF16*)var->name, name) == 0 )
            return var;
    }

    return NULL;
}

