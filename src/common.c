#include <stdint.h>

#include "common.h"
#include "storage.h"
#include "log.h"
#include "uefi/types.h"

/**
 * Return the length of a UTF16 string.
 *
 * Arg `str` MUST be null-terminated (2 bytes of zero).
 */
uint64_t strlen16(const UTF16 *str)
{
    uint64_t len = 0;
    const UTF16 *p1;

    if ( !str )
        return 0;

    p1 = str;

    while ( true )
    {
        /* Somthing is wrong if either pointers are null */
        if ( !p1 )
            break;

        /* zero pointers means we have reached the null-terminator */
        if ( *p1 == 0 )
            break;

        /*
         * We are processing two bytes at a time, so jump two bytes and
         * increment the length
         */
        p1 += 1;
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
    if ( !str )
        return 0;

    return strlen16(str) * sizeof(UTF16);
}

void uc2_ascii_safe(UTF16 *uc2, size_t uc2_len, char *ascii, size_t len)
{
    int i;

    if ( !uc2 || !ascii )
        return;

    for (i=0; i<uc2_len && i<len && uc2[i]; i++)
        ascii[i] = (char)uc2[i];

    ascii[i++] = '\0';
}

void uc2_ascii(UTF16 *uc2, char *ascii, size_t len)
{

    if ( !uc2 || !ascii )
        return;

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
    char buf[MAX_VARIABLE_NAME_SIZE] = {0};

    if ( !var )
        return;

    uc2_ascii_safe(var->name, var->namesz, buf, MAX_VARIABLE_NAME_SIZE);
    DEBUG("Variable(%s)\n", buf);
}

/**
 * print_variable -  print a variable
 *
 * WARNING: this only prints ASCII characters correctly.
 * Any char code above 255 will be displayed incorrectly.
 */

void print_variable(variable_t *var)
{
    char buf[MAX_VARIABLE_NAME_SIZE] = {0};

    if ( !var )
        return;

    uc2_ascii_safe(var->name, var->namesz, buf, MAX_VARIABLE_NAME_SIZE);
    printf("Variable(%s)\n", buf);
}

/**
 * Returns 0 if a and b are equal, otherwise non-zero.
 */
int strcmp16(const UTF16 *a, const UTF16 *b)
{
    size_t a_sz, b_sz;

    if ( !a || !b )
        return -1;

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
    UTF16 *p;
    size_t b_sz;

    if ( !a || !b )
        return -1;

    b_sz = strsize16(b);
    
    if ( b_sz + sizeof(UTF16) > n )
        return -1;

    memcpy(a, b, b_sz);

    p = a;
    p[b_sz / sizeof(UTF16)] = 0;

    return 0;
}

void dprint_data(void *data, size_t datasz)
{
    uint8_t *p = data;
    size_t i;

    if ( !data )
        return;

    DPRINTF("DATA: ");
    for (i=0; i<datasz; i++)
    {
        if (i % 8 == 0)
            DPRINTF("\n%02lx: 0x", i);
        DPRINTF("%02x", p[i]);
    }
    DPRINTF("\n");
}

variable_t *find_variable(const UTF16 *name, const EFI_GUID *guid, variable_t variables[MAX_VAR_COUNT], size_t n)
{
    variable_t *var;
    size_t i;

    if ( !name || !variables )
        return NULL;

    for ( i=0; i<n; i++ )
    {
        var = &variables[i];

        if ( strcmp16((UTF16*)var->name, name) == 0 &&
             memcmp(guid, &var->guid, sizeof(*guid)) == 0 )
            return var;
    }

    return NULL;
}

