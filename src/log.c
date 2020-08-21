#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

    if (ret < 0)
        ERROR("BUG: snprintf() error");

    _logfd = open(file_name, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);

    if (_logfd < 0)
        ERROR("failed to open %s, err: %d, %s\n", file_name, errno,
              strerror(errno));
}

void log_deinit(void)
{
    close(_logfd);
    _logfd = INVALID_FD;
}
