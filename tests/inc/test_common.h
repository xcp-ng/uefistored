#ifndef __H_COMMON_
#define __H_COMMON_

#include <stdio.h>

extern int passcount;
extern int failcount;
extern int all_passed;

#define test(assertion)                                                 \
    do {                                                                \
        printf("%s:%s:%d: %s: %s\n", __FILE__, __func__, __LINE__, #assertion, (assertion) ? "pass" : "fail");   \
        if ( !(assertion) )                                             \
            failcount++;                                                \
        else                                                            \
            passcount++;                                                \
    } while ( 0 )


#endif //  __H_COMMON_