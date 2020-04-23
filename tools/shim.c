#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int create_pidfile(char *pidfile, int pid)
{
    int fd;

    fd = open(pidfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if ( fd < 0 )
    {
        printf("failed to open %s, err: %d, %s\n", pidfile, errno, strerror(errno));
        return -1;
    }

    dprintf(fd, "%u\n", pid);
    return 0;
}

int main(int argc, char **argv)

{
    int option_index = 0;
    char *pidfile;
    int pid;
    char c;
    int ret;
    int pidfile_idx;
    int i;

    char **copy;
    char *p;

    const struct option options[] = {
        {"domain", required_argument,  0, 'd'},
        {"resume", no_argument,        0, 'r'},
        {"nonpersistent", no_argument, 0, 'n'},
        {"depriv", no_argument,        0, 'p'},
        {"uid", required_argument,     0, 'u'},
        {"gid", required_argument,     0, 'g'},
        {"chroot", required_argument,  0, 'c'},
        {"pidfile", required_argument, 0, 'i'},
        {"backend", required_argument, 0, 'b'},
        {"arg", required_argument, 0, 'a'},
        {"help", no_argument,          0, 'h'},
        {0, 0, 0, 0},
    };

    pid = getpid();

    while ( 1 )
    {
        c = getopt_long(argc, argv, "d:rnpu:g:c:i:b:ha:",
                        options, &option_index);

        /* Detect the end of the options. */
        if ( c == -1 )
            break;

        switch (c)
        {
        case 0:
        case 'd':
        case 'r':
        case 'n':
        case 'p':
        case 'u':
        case 'g':
        case 'c':
        case 'a':
            break;

        case 'i':
            pidfile = optarg;
            pidfile_idx = optind;
            ret = create_pidfile(pidfile, pid); 
            if ( ret < 0 )
            {
                printf("Failed to save pidfile\n");
            }

            break;


        case 'h':
        case '?':
        default:
            exit(1);
        }
    }

    int sz = argc + i;
    copy = malloc(sz * (sizeof(char*)));

    for (i=0; i<argc; i++)
    {
        p = argv[i];
        copy[i] = malloc(256);
        memset(copy[i], '\0', 256);
        strncpy(copy[i], argv[i], 256);
    }

    snprintf(copy[pidfile_idx], 256, "/tmp/tmp-%d.pid", getpid());
    copy[sz-1] = NULL;
    usleep(100000);
    execv("/root/varstored", copy);
    return 0;
}
