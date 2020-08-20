#include "sys/socket.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

static int sockfd;

int get_sockfd(void)
{
    return sockfd;
}

int socket(int type, int socktype, int protocol)
{
    sockfd = open("./mock_socket", O_RDWR | O_CREAT | O_EXCL, S_IRWXU);

    if (sockfd == -1)
        return sockfd;

    return sockfd;
}
