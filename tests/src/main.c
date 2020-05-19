#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#include "test_xenvariable.h"
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
    test_xenvariable();

    printf("PASSED (%d), FAILED (%d)\n", passcount, failcount);
    return failcount == 0 ? 0 : -1;
}
