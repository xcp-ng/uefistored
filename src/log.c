#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "storage.h"
#include "log.h"

/**
 * Print UTF16 variable name.
 */
void dprint_name(const UTF16 *name, size_t namesz)
{
    char buf[MAX_VARIABLE_NAME_SIZE] = { 0 };

    if (loglevel < LOGLEVEL_DEBUG || !name)
        return;

    uc2_ascii_safe(name, namesz, buf, MAX_VARIABLE_NAME_SIZE);
    DPRINTF("%s (%lu)", buf, namesz);
}

/**
 * Debug print a variable.
 *
 * NOTE: this only prints ASCII characters correctly.
 * Any char code above 255 will be skipped.
 */
void dprint_variable(const variable_t *var)
{
    if (loglevel < LOGLEVEL_DEBUG || !var)
        return;

    dprint_name(var->name, var->namesz);
    DPRINTF(", guid=0x%02llx", *((unsigned long long*)&var->guid));
    DPRINTF(", attrs=0x%02x, ", var->attrs);
    dprint_data(var->data, var->datasz);
    if (var->attrs & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
        DPRINTF(", Time<Year=%u, Month=%u, Day=%u, Hour=%u, Minute=%u, Second=%u>",
                var->timestamp.Year, var->timestamp.Month, var->timestamp.Day,
                var->timestamp.Hour, var->timestamp.Minute,
                var->timestamp.Second);
    DPRINTF("\n");
}

/**
 * Print a list of variables.
 */
void dprint_variable_list(const variable_t *vars, size_t n)
{
    size_t i;

    if (loglevel < LOGLEVEL_DEBUG || !vars)
        return;

    for (i = 0; i < n; i++) {
        dprint_variable(&vars[i]);
    }
}

void dprint_data(const void *data, size_t datasz)
{
    const uint8_t *p = data;
    size_t i;

    if (loglevel < LOGLEVEL_DEBUG)
        return;

    if (!data)
        return;

    DPRINTF("data(%lu)=[", datasz);
    for (i = 0; i < datasz; i++) {
        DPRINTF("0x%02x ", p[i]);

        if (i < datasz - 1)
            DPRINTF(", ");
    }
    DPRINTF("]\n");
}
