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
