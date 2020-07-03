#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "common.h"
#include "log.h"
#include "test_common.h"
#include "test_xapi.h"
#include "test_xenvariable.h"
#include "test_ramdb.h"

#define LOGFILE "test_logfile.txt"

int passcount = 0;
int failcount = 0;

int open_logfile(void)
{
    return open(LOGFILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
}

int main(void)
{ 
    log_init(LOGFILE);
    test_xenvariable();
    test_xapi();
    test_ramdb();

    printf("PASSED (%d), FAILED (%d)\n", passcount, failcount);
    return failcount == 0 ? 0 : -1;
}
