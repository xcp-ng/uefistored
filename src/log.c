#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "storage.h"
#include "log.h"

#define LOG_FILE_MAX 64
#define INVALID_FD (-1)

char strbuf[512];
static char file_name[LOG_FILE_MAX] = { 0 };
int _logfd = INVALID_FD;

void log_init(unsigned int domid)
{
    int ret;


    ret = mkdir("/var/log/uefistored/", S_IRUSR | S_IWUSR | S_IXUSR);

    if (ret < 0 && errno != EEXIST) {
        ERROR("mkdir() failed: %d, %s\n", errno, strerror(errno));
        return;
    }

    ret = snprintf(file_name, LOG_FILE_MAX,
                   "/var/log/uefistored/%u.log", domid);

    if (ret < 0) {
        ERROR("BUG: snprintf() error");
        return;
    }

    _logfd = open(file_name, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);

    if (_logfd < 0) {
        ERROR("failed to open %s, err: %d, %s\n", file_name, errno,
              strerror(errno));
        return;
    }

    DDEBUG("Log initialized\n");
}

void log_deinit(void)
{
    close(_logfd);
    _logfd = INVALID_FD;
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

