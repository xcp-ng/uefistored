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

#include <xenctrl.h>
#include <xenstore.h>
#include <xendevicemodel.h>
#include <xenevtchn.h>
#include <xentoolcore.h>
#include <xenforeignmemory.h>
#include <xen/hvm/dm_op.h>
#include <xen/hvm/ioreq.h>
#include <xen/hvm/params.h>
#include <xen/io/ring.h>
#include <xen/memory.h>

#include "common.h"
#include "xen_hvm.h"

#define IOREQ_SERVER_TYPE 0
#define IOREQ_SERVER_FRAME_NR 2

#define STRINGBUF_MAX 0x40
#define PIDSTRING_MAX 16

#define USAGE                           \
    "Usage: varstored <options> \n"   \
    "\n"                                \
    "    --domain <domid> \n"           \
    "    --resume \n"                   \
    "    --nonpersistent \n"            \
    "    --depriv \n"                   \
    "    --uid <uid> \n"                \
    "    --gid <gid> \n"                \
    "    --chroot <chroot> \n"          \
    "    --pidfile <pidfile> \n"        \
    "    --backend <backend> \n"        \
    "    --arg <name>:<val> \n\n"

#define UNIMPLEMENTED(opt)                                      \
        ERROR(opt " option not implemented!\n")

xendevicemodel_handle *xen_dmod = NULL;
xenforeignmemory_handle *xen_fmem = NULL;
int xen_domid = -1;
int some_static_var;
ioservid_t _ioservid;
const unsigned long portio_port_start = 0x100;
const unsigned long portio_port_end = 0x103;

#define TARGET_PAGE_SIZE (1<<12)

#if 0
static void do_many_allocs_and_memcmp(int ret)
{
    (void) ret;
}

#define IOREQ_PFN_NR 16

static void do_xenforeignmemory_map(void *p,pfn_t *pfn)
{
    void *p;
    int ret;
    int i;
    unsigned long array [IOREQ_PFN_NR];

    if ( p == 0 )
    {
        for (i=0; i<16; i++)
        {
            array[i] = (unsigned long) pfn[i];
        }

        ret = xenforeignmemory_map(xen_fmem, xen_domid, 3, IOREQ_PFN_NR, array,0);
        if ( ret != 0 )
        {
            do_many_allocs_and_memcmp(i);
            xenforeignmemory_unmap(xen_fmem, p, IOREQ_PFN_NR);
            return;
        }
    }
    return;
}
#endif

#define MB(x) (x << 20)

#if 0
#define AUTH_FILE "/auth/file/path/"
static void *auth_file;
static int load_auth_file(void)
{
    int fd;
    ssize_t read_size;
    int ret;
    struct stat stat;
    FILE *stream;

    stream = fopen(AUTH_FILE, "r");
    if ( !stream )
    {
        if ( errno == 2 )
        {
            ERROR("Auth file %s is missing!\n");
        }
        else
        {
            ERROR("Failed to open %s\n", AUTH_FILE);
        }

        ret = errno;
        goto error;
    }

    fd = fileno(stream);
    if ( fd < 0 )
    {
        ERROR("Not a file!\n");
        ret = errno;
        goto error;
    }

    ret = fstat(fd, &stat);
    if ( ret == -1 )
    {
        ERROR("Failed to stat \'%s\'\n", AUTH_FILE);
        goto error;
    }

    if ( stat.st_size > MB(1) )
    {
        ERROR("Auth file too large: %luMB\n", stat.st_size >> 20);
        goto error;
    }

    auth_file = malloc((size_t) stat.st_size);
    if ( !auth_file )
    {
        ERROR("Out of memory!\n");
        goto error;
    }

    read_size = fread(auth_file, 1, (size_t)stat.st_size, stream);
    if ( read_size != stat.st_size )
    {
        ERROR("Failed to read \'%s\'\n", AUTH_FILE);
        goto error;
    }

    fclose(stream);
    return 0;


error:
    if ( auth_file )
        free(auth_file);

    fclose(stream);
    return ret;
}
#endif

static char *varstored_xs_read_string(struct xs_handle *xsh, const char *xs_path, int domid, unsigned int *len)
{
    char stringbuf[STRINGBUF_MAX];

    snprintf(stringbuf, STRINGBUF_MAX, xs_path, domid);
    return xs_read(xsh, XBT_NULL, stringbuf, len);
}

static bool varstored_xs_read_bool(struct xs_handle *xsh, const char *xs_path, int domid)
{
    char *data;
    unsigned int len;

    data = varstored_xs_read_string(xsh, xs_path, domid, &len);
    if ( !data )
        return false;

    return strncmp(data, "true", len) == 0;
}


int create_pidfile(char *pidfile, int pid)
{
    int fd;

    fd = open(pidfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if ( fd < 0 )
    {
        ERROR("failed to open %s, err: %d, %s\n", pidfile, errno, strerror(errno));
        return -1;
    }

    dprintf(fd, "%u\n", pid);
    return 0;
}


int main(int argc, char **argv)

{
    xc_interface *xc_handle;
    xc_dominfo_t domain_info;
    xenevtchn_handle *xce;
    struct xs_handle *xsh;
    bool secureboot_enabled;
    bool enforcement_level;
    uint64_t ioreq_server_pages_cnt;
    ioservid_t ioservid;
    char stringbuf[STRINGBUF_MAX];
    int option_index = 0;
    char *pidfile;
    char pidstring[PIDSTRING_MAX];
    uint32_t nr_online_vcpus;
    int pid;
    int i;
    char c;
    int ret;

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

    if ( argc == 1 )
    {
        printf(USAGE);
        exit(1);
    }

    if ( init_log() < 0 )
        printf("Log failed to initialize\n");

    DEBUG("%d: Starting parsing args...\n", __LINE__);

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
            /* If this option set a flag, do nothing else now. */
            if ( options[option_index].flag != 0 )
                break;

            printf ("option %s", options[option_index].name);
            if ( optarg )
                printf (" with arg %s", optarg);
            printf ("\n");
            break;

        case 'd':
            xen_domid = atoi(optarg);
            INFO("servicing UEFI variables for Domain %d\n", xen_domid);
            break;

        case 'r':
            UNIMPLEMENTED("resume");
            break;

        case 'n':
            UNIMPLEMENTED("nonpersistent");
            break;

        case 'p':
            UNIMPLEMENTED("depriv");
            break;

        case 'u':
            UNIMPLEMENTED("uid");
            break;

        case 'g':
            UNIMPLEMENTED("gid");
            break;

        case 'c':
            UNIMPLEMENTED("chroot");
            break;

        case 'i':
            pidfile = optarg;
            ret = create_pidfile(pidfile, pid); 
            if ( ret < 0 )
            {
                DEBUG("Failed to save pidfile\n");
            }
            break;

        case 'b':
            UNIMPLEMENTED("backend");
            break;

        case 'a':
            UNIMPLEMENTED("arg");
            break;

        case 'h':
        case '?':
        default:
            printf(USAGE);
            exit(1);
        }
    }

    usleep(100000);


    // TODO: implement signal handlers in order to tear down resources upon SIGKILL, etc...

    /* Gain access to the hypervisor */
    xc_handle = xc_interface_open(0, 0, 0);
    if ( !xc_handle )
    {
        ERROR("Failed to open xc_interface handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto error;
    }
    DEBUG("%d: xc_interface_open()\n", __LINE__);

    /* Get info on the domain */
    ret = xc_domain_getinfo(xc_handle, xen_domid, 1, &domain_info);
    if ( ret < 0 )
    {
        ret = errno;
        ERROR("Domid %u, xc_domain_getinfo error: %d, %s\n", xen_domid, errno, strerror(errno));
        goto cleanup;
    }
    /* Verify the requested domain == the returned domain */
    if ( xen_domid != domain_info.domid )
    {
        ret = errno;
        ERROR("Domid %u does not match expected %u\n", domain_info.domid, xen_domid);
        goto cleanup;
    }

    nr_online_vcpus = domain_info.nr_online_vcpus;

    /* Retrieve IO req server page count, retry until available */
    for ( i=0; i<10; i++ )
    {
        ret = xc_hvm_param_get(xc_handle, xen_domid, HVM_PARAM_NR_IOREQ_SERVER_PAGES, &ioreq_server_pages_cnt);
        if ( ret < 0 )
        {
            ERROR("xc_hvm_param_get failed: %d, %s\n", errno, strerror(errno));
            goto cleanup;
        }
        DEBUG("%d: xc_hvm_param_get()\n", __LINE__);

        if ( ioreq_server_pages_cnt != 0 )
            break;

        printf("Waiting for ioreq server");
        usleep(100000);
    }
    INFO("HVM_PARAM_NR_IOREQ_SERVER_PAGES = %ld\n", ioreq_server_pages_cnt);

    /* Open xen device model */
    xen_dmod = xendevicemodel_open(0, 0);
    if ( !xen_dmod )
    {
        ERROR("Failed to open xendevicemodel handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto cleanup;
    }

    /* Open xen foreign memory interface */
    xen_fmem = xenforeignmemory_open(0, 0);
    if ( !xen_fmem )
    {
        ERROR("Failed to open xenforeignmemory handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto cleanup;
    }

    /* Open xen event channel */
    xce = xenevtchn_open(NULL, 0);
    if ( !xce )
    {
        ERROR("Failed to open evtchn handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto cleanup;
    }

    /* Restrict varstored's privileged accesses */
    ret = xentoolcore_restrict_all(xen_domid);
    if ( ret < 0 )
    {
        ERROR("Failed to restrict Xen handles: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto cleanup;
    }

    /* Create an IO Req server for Port IO requests in the port
     * range 0x100 to 0x103.  XenVariable in OVMF uses 0x100,
     * 0x101-0x103 are reserved.
     */
    ret = xendevicemodel_create_ioreq_server(xen_dmod, xen_domid,
                                             HVM_IOREQSRV_BUFIOREQ_LEGACY, &ioservid);
    if ( ret < 0 )
    {
        ERROR("Failed to create ioreq server: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto cleanup;
    }

    INFO("ioservid = %u\n", ioservid);
    DEBUG("Mapped ioreq server\n");

    /* Initialize Port IO for domU */
    INFO("%d vCPU(s)\n", nr_online_vcpus);

    xsh = xs_open(0);
    if ( !xsh )
    {
        ERROR("Couldn\'t open xenstore: %d, %s", errno, strerror(errno));
        goto cleanup;
    }

    /* Check secure boot is enabled */
    secureboot_enabled = varstored_xs_read_bool(xsh, "/local/domain/%u/platform/secureboot", xen_domid);
    INFO("Secure boot enabled: %s\n", secureboot_enabled ? "true" : "false");

    /* Check enforcment level */
    enforcement_level = varstored_xs_read_bool(xsh, "/local/domain/%u/platform/auth-enforce", xen_domid);
    INFO("Authenticated variables: %s\n", enforcement_level ? "enforcing" : "permissive");

    /* Store the varstored pid in XenStore */
    ret =  snprintf(stringbuf, STRINGBUF_MAX, "/local/domain/%u/varserviced-pid", xen_domid);
    if ( ret < 0 )
    {
        ERROR("buffer error: %d, %s\n", errno, strerror(errno));
        goto cleanup;
    }

    ret = snprintf(pidstring, PIDSTRING_MAX, "%d", pid);
    if ( ret < 0 )
    {
        ERROR("buffer error: %d, %s\n", errno, strerror(errno));
        goto cleanup;
    }

    ret = xs_write(xsh, XBT_NULL, stringbuf, pidstring, ret);
    if ( ret == false )
    {
        ERROR("xs_write failed: %d, %s\n", errno, strerror(errno));
        goto cleanup;
    }

    /* TODO: Containerize varstored */

    /* TODO: Initialize UEFI variables */

    /* TODO: Initialize UEFI keys */

    INFO("Starting handler loop!\n");
    xen_hvm_init();
    return 0;

cleanup:
    if ( xce )
        xenevtchn_close(xce);

    if ( xen_fmem )
        xenforeignmemory_close(xen_fmem);

    if ( xen_dmod )
        xendevicemodel_close(xen_dmod);

    if ( xc_handle )
        xc_interface_close(xc_handle);

#if 0
    xenevtchn_unbind(xenevtchn_handle);
    xenevtchn_unbind(xenevtchn_handle);
    xendevicemodel_destroy_ioreq_server(xendevicemodel_handle,(ulong)domain,(ulong)ioservid);

    xendevicemodel_set_ioreq_server_state
    (xendevicemodel_handle,(ulong)domain,(ulong)ioservid,0);
#endif
error:
    return ret;
}

