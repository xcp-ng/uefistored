#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "parse.h"

#define test(assertion)                                                 \
    do {                                                                \
        printf("%s: %s\n", #assertion, (assertion) ? "pass" : "fail");   \
        if ( !(assertion) )                                             \
            all_passed = 0;                                             \
    } while ( 0 )

int all_passed = 1;

static const uint8_t GET_RTC[] = {
#include "data/get_rtc.txt"
};

static const uint8_t SET_RTC[] = {
#include "data/set_rtc.txt"
};

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

    /* Test that the variable fields parse correctly */
    parse_variable_name(message, &variable_name, &len);
    test(memcmp(variable_name, UEFI_RTC_STR, len) == 0);
    test(len == sizeof(UEFI_RTC_STR));

    /* Free up any used memory */
    free(variable_name);
}

void test_set_rtc(void)
{
    uint8_t guid[16];
    size_t len;
    size_t datalen;
    void *message;
    void *variable_name;
    void *data;
    
    /* SET_VARIABLE "RTC" tests */
    message = (void*) SET_RTC;

    /* Test the command and version parse correctly */
    test(parse_command(message) == COMMAND_SET_VARIABLE);
    test(parse_version(message) == 1);

    /* Test that the variable fields parse correctly */
    parse_variable_name(message, &variable_name, &len);
    test(memcmp(variable_name, UEFI_RTC_STR, len) == 0);
    test(len == sizeof(UEFI_RTC_STR));

    /* Test that the GUID is parsed correctly */
    parse_guid(message, guid);
    test(memcmp(guid, &SET_RTC[22], 16) == 0);

    /* Test that the data is parsed correctly */
    parse_data(message, &data, &datalen);
    test(datalen == 0x04);

    size_t *sp = (size_t*)&SET_RTC[38];
    test(*sp == 0x04);
    test(memcmp(data, &SET_RTC[38 + 4], 0x04) == 0);

    test(parse_attr(message) == 7);
    test(parse_efiruntime(message) == 0);

    /* Free up any used memory */
    free(variable_name);
}

int main(void)
{
    test_get_rtc();
    test_set_rtc();
    printf("%s\n", all_passed ? "ALL PASSED" : "FAILED");
    return all_passed ? 0 : -1;
}
