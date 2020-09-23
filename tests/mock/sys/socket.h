#ifndef __H_MOCK_SOCKET_
#define __H_MOCK_SOCKET_

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

#define AF_LOCAL 1
#define AF_UNIX AF_LOCAL
#define SOCK_STREAM 1

#define MEMFD_SIZE 4096

struct sockaddr {
    uint64_t sun_family;
    char sun_path[108];
};

int socket(int type, int socktype, int protocol);
int get_sockfd(void);

static inline int connect(int fd, const struct sockaddr *addr, uint64_t addrlen)
{
    return 0;
}

#endif // __H_MOCK_SOCKET_
