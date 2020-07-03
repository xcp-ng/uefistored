#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <unistd.h>

#include "log.h"

#define LOG_FILE_MAX 64
#define INVALID_FD (-1)

char strbuf[512];
static char *logfile_name;
int _logfd = INVALID_FD;

void log_init(const char *filename)
{
    int ret;

    if ( !filename )
    {
        logfile_name = malloc(LOG_FILE_MAX);

        if ( !logfile_name )
        {
            ERROR("failed to allocate log filename\n");
            return;
        }

        memset(logfile_name, '\0', LOG_FILE_MAX);

        ret = snprintf(logfile_name, LOG_FILE_MAX, "/var/log/varstored-%d.log", getpid());

        if ( ret < 0 )
            ERROR("BUG: snprintf() error");

        _logfd = open(logfile_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    }
    else
    {
        _logfd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    }

    if ( _logfd < 0 )
        ERROR("failed to open %s, err: %d, %s\n", filename, errno, strerror(errno));
}

void log_deinit(void)
{
    if ( logfile_name )
        free(logfile_name);

    close(_logfd);
    _logfd = INVALID_FD;
}
