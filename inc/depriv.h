#ifndef __H_DEPRIV_
#define __H_DEPRIV_

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

bool drop_privileges(const char *opt_chroot, bool opt_depriv, gid_t opt_gid,
                     uid_t opt_uid);

#endif // __H_DEPRIV_
