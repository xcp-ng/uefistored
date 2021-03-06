#ifndef __H_CONFIG_
#define __H_CONFIG_

#define UEFISTORED_VERSION 1

/* utility macros for configs */
#define KB(x) (x * 1024)
#define MB(x) (KB(x) * 1024)

#define MAX_VAR_COUNT 128
#define MAX_VARIABLE_NAME_SIZE 256
#define MAX_VARIABLE_NAME_CHARS (MAX_VARIABLE_NAME_SIZE / 2)
#define MAX_VARIABLE_DATA_SIZE KB(32)
#define MAX_VARIABLE_SIZE (MAX_VARIABLE_NAME_SIZE + MAX_VARIABLE_DATA_SIZE)
#define MAX_STORAGE_SIZE (MAX_VAR_COUNT * MAX_VARIABLE_NAME_SIZE * MAX_VARIABLE_DATA_SIZE)

#endif // __H_CONFIG_
