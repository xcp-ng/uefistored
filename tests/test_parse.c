#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "parse.h"

int all_passed = 1;

static const uint8_t GET_RTC[] = {
#include "data/get_rtc.txt"
};

#define test(assertion)                                                 \
    do {                                                                \
        printf("%s: %s\n", #assertion, (assertion) ? "pass" : "fail");   \
        if ( !(assertion) )                                             \
            all_passed = 0;                                             \
    } while ( 0 )

/* UEFI uses 16-bit fixed-width encoding, RTC (3 chars) has length 6 */
const char UEFI_RTC_STR[] = { 'R', '\0', 'T', '\0', 'C', '\0' }; 

void test_get_rtc(void)
{
    size_t len;
    void *message;
    void *variable_name;
    
    /* GET_VARIABLE "RTC" tests */
    message = (void*) GET_RTC;

    /* Test the command and version parse correctly */
    test(parse_command(message) == COMMAND_GET_VARIABLE);
    test(parse_version(message) == 1);

    /* Test that the variable fields parse correctly*/
    parse_variable_name(message, &variable_name, &len);
    test(memcmp(variable_name, UEFI_RTC_STR, len) == 0);
    test(len == sizeof(UEFI_RTC_STR));

    /* Free up any used memory */
    free(variable_name);
}


int main(void)
{
    test_get_rtc();
    printf("%s\n", all_passed ? "ALL PASSED" : "FAILED");
    return all_passed ? 0 : -1;
}

