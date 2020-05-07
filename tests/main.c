#include "test_parse.h"
#include "test_xenvar.h"
#include "test_xenvariable.h"
#include "test_common.h"

int passcount = 0;
int failcount = 0;

int main(void)
{
    test_get_rtc();
    test_set_rtc();
    test_get_next();
    test_xenvar();
    test_xenvariable();

    printf("PASSED (%d), FAILED (%d)\n", passcount, failcount);
    return failcount == 0 ? 0 : -1;
}
