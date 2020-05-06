#ifndef __H_COMMON_
#define __H_COMMON_

#include <stdio.h>

extern int all_passed;

#define test(assertion)                                                 \
    do {                                                                \
        printf("%s: %s\n", #assertion, (assertion) ? "pass" : "fail");   \
        if ( !(assertion) )                                             \
            all_passed = 0;                                             \
    } while ( 0 )


#endif //  __H_COMMON_
