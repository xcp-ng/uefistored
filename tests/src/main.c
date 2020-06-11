#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "test_auth.h"
#include "test_xenvariable.h"
#include "test_ramdb.h"
#include "test_xapi.h"
#include "test_common.h"
#include "common.h"

#define LOGFILE "test_logfile.txt"

int logfd = -1;
int passcount = 0;
int failcount = 0;

int open_logfile(void)
{
    return open(LOGFILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
}

int main(void)
{ 
    set_logfd(open_logfile());
#if 1
    test_xenvariable();
    test_xapi();
    test_ramdb();
#endif
    test_auth();

    printf("PASSED (%d), FAILED (%d)\n", passcount, failcount);
    return failcount == 0 ? 0 : -1;
}
