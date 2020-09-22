#include <ctype.h>
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

    if (!str)
        return 0;

    p1 = str;

    while (true) {
        /* Somthing is wrong if either pointers are null */
        if (!p1)
            break;

        /* zero means we have reached the null-terminator */
        if (*p1 == 0)
            break;

        /*
         * We are processing two bytes at a time, so jump two bytes and
         * increment the length
         */
        p1++;
        len++;
    }

    return len;
}

/**
 * Returns the size of the string in total bytes.
 */
uint64_t strsize16(const UTF16 *str)
{
    if (!str)
        return 0;

    return (strlen16(str) + 1) * sizeof(UTF16);
}

void uc2_ascii_safe(const UTF16 *uc2, size_t uc2_len, char *ascii, size_t len)
{
    int i;

    if (!uc2 || !ascii)
        return;

    for (i = 0; i < uc2_len && i < len && uc2[i]; i++)
        ascii[i] = (char)uc2[i];

    ascii[i++] = '\0';
}

void uc2_ascii(const UTF16 *uc2, char *ascii, size_t len)
{
    if (!uc2 || !ascii)
        return;

    uc2_ascii_safe(uc2, strsize16(uc2), ascii, len);
}

void dprint_name(const UTF16 *name, size_t namesz)
{
    char buf[MAX_VARIABLE_NAME_SIZE] = { 0 };

    if (!name)
        return;

    uc2_ascii_safe(name, namesz, buf, MAX_VARIABLE_NAME_SIZE);
    DPRINTF("Variable(%s)", buf);
}

/**
 * dprint_variable -  Debug print a variable
 *
 * WARNING: this only prints ASCII characters correctly.
 * Any char code above 255 will be displayed incorrectly.
 */

void dprint_variable(const variable_t *var)
{
    if (!var)
        return;

    dprint_name(var->name, var->namesz);
    DPRINTF(", guid=0x%02x",var->guid.Data1);
    DPRINTF(", attrs=0x%02x, ", var->attrs);
    dprint_data(var->data, var->datasz);
    if (var->attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
        DPRINTF(", Time<Year=%u, Month=%u, Day=%u, Hour=%u, Minute=%u, Second=%u>",
                var->timestamp.Year, var->timestamp.Month, var->timestamp.Day,
                var->timestamp.Hour, var->timestamp.Minute, var->timestamp.Second);
    DPRINTF("\n");
}

void dprint_variable_list(const variable_t *vars, size_t n)
{
    size_t i;

    if (!vars)
        return;

    for (i = 0; i < n; i++) {
        dprint_variable(&vars[i]);
    }
}

/**
 * Returns 0 if a and b are equal, otherwise non-zero.
 */
int strcmp16(const UTF16 *a, const UTF16 *b)
{
    size_t a_sz, b_sz;

    if (!a || !b)
        return -1;

    a_sz = strsize16(a);
    b_sz = strsize16(b);

    if (a_sz != b_sz) {
        return -1;
    }

    return memcmp(a, b, min(a_sz, b_sz));
}

/**
 * Copies string `b` to string `a`.
 */
int strncpy16(UTF16 *a, const UTF16 *b, const size_t n)
{
    size_t b_sz;

    if (!a || !b)
        return -1;

    b_sz = strsize16(b);

    if (b_sz > n)
        return -1;

    memcpy(a, b, b_sz);

    return 0;
}

void dprint_data(const void *data, size_t datasz)
{
    const uint8_t *p = data;
    size_t i;

    if (!data)
        return;

    DPRINTF("data(%lu)=", datasz);
    for (i = 0; i < 8 && i < datasz; i++) {
        DPRINTF("0x%02x ", p[i]);
    }
}

variable_t *find_variable(const UTF16 *name, const EFI_GUID *guid,
                          variable_t *variables, size_t n)
{
    variable_t *var;
    size_t i;

    if (!name || !variables || !guid)
        return NULL;

    for (i = 0; i < n; i++) {
        var = &variables[i];

        if (strcmp16((UTF16 *)var->name, name) == 0 &&
            memcmp(guid, &var->guid, sizeof(EFI_GUID)) == 0)
            return var;
    }

    return NULL;
}

/**
 * Remove any white space from ends of string.
 */
char *strstrip(char *s)
{
    size_t size;
    char *end;

    size = strlen(s);

    if (!size)
        return s;

    end = s + size - 1;

    while (end >= s && isspace(*end))
        end--;

    *(end + 1) = '\0';

    while (*s && isspace(*s))
        s++;

    return s;
}

const char *efi_status_str(EFI_STATUS status)
{
    switch (status) {
    case EFI_SUCCESS:
        return "EFI_SUCCESS";
    case EFI_INVALID_PARAMETER:
        return "EFI_INVALID_PARAMETER";
    case EFI_UNSUPPORTED:
        return "EFI_UNSUPPORTED";
    case EFI_DEVICE_ERROR:
        return "EFI_DEVICE_ERROR";
    case EFI_NOT_FOUND:
        return "EFI_NOT_FOUND";
    case EFI_BUFFER_TOO_SMALL:
        return "EFI_BUFFER_TOO_SMALL";
    case EFI_OUT_OF_RESOURCES:
        return "EFI_OUT_OF_RESOURCES";
    case EFI_SECURITY_VIOLATION:
        return "EFI_SECURITY_VIOLATION";
    default:
        return "UNKNOWN";
    }

    return "UNKNOWN";
}
