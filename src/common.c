#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "common.h"

#define VARSTORED_LOGFILE "/var/log/varstored-%d.log"
#define VARSTORED_LOGFILE_MAX 32

int _logfd = NULL;

int init_log(void)
{
    int ret;
    int logfd;
    char *log_filename;

    log_filename = malloc(VARSTORED_LOGFILE_MAX);
    memset(log_filename, '\0', VARSTORED_LOGFILE_MAX);

    ret = snprintf(log_filename, VARSTORED_LOGFILE_MAX,  VARSTORED_LOGFILE, getpid());
    if ( ret < 0 )
    {
        ERROR("BUG: snprintf() error");
        goto error;
    }

    logfd = open(log_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if ( logfd < 0 )
    {
        ERROR("failed to open %s, err: %d, %s\n", log_filename, errno, strerror(errno));
        ret = errno;
        goto error;
    }

    _logfd = logfd;
    return 0;

error:
    free(log_filename);
    return ret;
}
