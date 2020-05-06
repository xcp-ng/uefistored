#include "test_parse.h"
#include "test_xenvar.h"
#include "common.h"

int all_passed = 1;

int main(void)
{
    test_get_rtc();
    test_set_rtc();
    test_get_next();
    test_xenvar();
    printf("%s\n", all_passed ? "ALL PASSED" : "FAILED");
    return all_passed ? 0 : -1;
}
