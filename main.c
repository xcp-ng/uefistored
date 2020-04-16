#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <xenctrl.h>
#include <xendevicemodel.h>
#include <xenevtchn.h>
#include <xenforeignmemory.h>
#include <xen/hvm/dm_op.h>
#include <xen/hvm/ioreq.h>
#include <xen/hvm/params.h>
#include <xen/memory.h>

#define IOREQ_SERVER_TYPE 0
#define IOREQ_SERVER_FRAME_NR 2

#define VARSTORED_LOGFILE "/var/log/varstored-%d.log"
#define VARSTORED_LOGFILE_MAX 32

static int _logfd = NULL;

static inline void set_logfd(int logfd)
{
    _logfd = logfd;
}

#define varstored_dprintf(fd, ...)                    \
    do {                                                \
        dprintf(fd, "varstored_initialize: ");        \
        dprintf(fd, __VA_ARGS__);                       \
    } while( 0 )

#define varstored_fprintf(stream, ...)                    \
    do {                                                \
        fprintf(stream, "varstored_initialize: ");        \
        fprintf(stream, __VA_ARGS__);                       \
        fflush(stream);                                     \
    } while( 0 )

#define ERROR(...)                                                  \
    do {                                                            \
        varstored_fprintf(stderr, "ERROR: " __VA_ARGS__);           \
        if ( _logfd )                                                 \
            varstored_dprintf(_logfd, "ERROR: " __VA_ARGS__);       \
    } while ( 0 )

#define INFO(...)                                                   \
    do {                                                            \
        varstored_fprintf(stdout,  "INFO: "   __VA_ARGS__);         \
        if ( _logfd )                                                 \
            varstored_dprintf(_logfd,  "INFO: "   __VA_ARGS__);     \
    } while ( 0 )

#define DEBUG(...)                                              \
    do {                                                        \
        varstored_fprintf(stdout, "DEBUG: " __VA_ARGS__);       \
        if ( _logfd )                                             \
            varstored_dprintf(_logfd, "DEBUG: "  __VA_ARGS__);   \
    } while ( 0 )

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

#define TRACE()  DEBUG("%s: %d\n", __func__, __LINE__)

static inline int xen_get_ioreq_server_info(xc_interface *xc,
                                            domid_t dom,
                                            xen_pfn_t *ioreq_pfn,
                                            xen_pfn_t *bufioreq_pfn,
                                            evtchn_port_t *bufioreq_evtchn)
{
    unsigned long param;
    int rc;

    if ( !ioreq_pfn )
    {
        ERROR("invalid NULL ioreq_pfn in %s\n", __func__);
        return -EINVAL;
    }

    if ( !bufioreq_pfn )
    {
        ERROR("invalid NULL bufioreq_pfn in %s\n", __func__);
        return -EINVAL;
    }

    if ( !bufioreq_evtchn )
    {
        ERROR("invalid NULL bufioreq_evtchn in %s\n", __func__);
        return -EINVAL;
    }

    if ( !xc )
    {
        ERROR("invalid NULL xc ptr in %s\n", __func__);
        return -EINVAL;
    }


    DEBUG("%s: domid=%d\n", __func__, dom);

    TRACE();
    rc = xc_hvm_param_get(xc, dom, HVM_PARAM_IOREQ_PFN, &param);
    if ( rc < 0 )
    {
        TRACE();
        ERROR("failed to get HVM_PARAM_IOREQ_PFN\n");
        return -1;
    }

    TRACE();
    *ioreq_pfn = param;

    TRACE();

    rc = xc_hvm_param_get(xc, dom, HVM_PARAM_BUFIOREQ_PFN, &param);
    if ( rc < 0 )
    {
        ERROR("failed to get HVM_PARAM_BUFIOREQ_PFN\n");
        return -1;
    }
    TRACE();
    *bufioreq_pfn = param;

    TRACE();

    rc = xc_hvm_param_get(xc, dom, HVM_PARAM_BUFIOREQ_EVTCHN,
                          &param);
    if ( rc < 0 )
    {
        ERROR("failed to get HVM_PARAM_BUFIOREQ_EVTCHN\n");
        return -1;
    }
    *bufioreq_evtchn = param;

    TRACE();

    return 0;
}

#warning "Determine this page size correctly, are all supported page sizes 4KB?"
#define TARGET_PAGE_SIZE (4<<12)

static int xen_map_ioreq_server(xc_interface* xc_handle,
                                xenforeignmemory_handle *fmem,
                                domid_t domid,
                                ioservid_t ioservid,
                                shared_iopage_t **shared_page,
                                buffered_iopage_t **buffered_io_page,
                                evtchn_port_t *bufioreq_remote_port,
                                xenforeignmemory_resource_handle **fres)
{
    void *addr = NULL;
    xen_pfn_t ioreq_pfn;
    xen_pfn_t bufioreq_pfn;
    evtchn_port_t bufioreq_evtchn;
    int rc;

    DEBUG("%s: %d\n", __func__, __LINE__);

    /*
     * Attempt to map using the resource API and fall back to normal
     * foreign mapping if this is not supported.
     */
    *fres = xenforeignmemory_map_resource(fmem, domid,
                                         XENMEM_resource_ioreq_server,
                                         ioservid, 0, 2,
                                         &addr,
                                         PROT_READ | PROT_WRITE, 0);
    if ( *fres != NULL )
    {
        *buffered_io_page = addr;
        *shared_page = addr + TARGET_PAGE_SIZE;
    }
    else if ( errno != EOPNOTSUPP )
    {
        ERROR("failed to map ioreq server resources: error %d: %s",
                     errno, strerror(errno));
        return -1;
    }

    DEBUG("%s: %d\n", __func__, __LINE__);

    rc = xen_get_ioreq_server_info(xc_handle, domid,
                                   &ioreq_pfn,
                                   &bufioreq_pfn,
                                   &bufioreq_evtchn);
    if ( rc < 0 )
    {
        ERROR("failed to get ioreq server info: error %d: %s",
                     errno, strerror(errno));
        return rc;
    }

    DEBUG("%s: %d\n", __func__, __LINE__);

    if ( *shared_page == NULL)
    {
        DEBUG("%d: shared page at pfn %lx\n", __LINE__, ioreq_pfn);
        *shared_page = xenforeignmemory_map(fmem, domid,
                                            PROT_READ | PROT_WRITE,
                                            1, &ioreq_pfn, NULL);
        if ( *shared_page == NULL )
        {
            ERROR("map shared IO page returned error %d: %s",
                   errno, strerror(errno));
        }
    }
    DEBUG("%s: %d\n", __func__, __LINE__);

    if ( *buffered_io_page == NULL )
    {
        DEBUG("%d: buffered io page at pfn %lx\n", __LINE__, bufioreq_pfn);

        *buffered_io_page = xenforeignmemory_map(fmem, domid,
                                                       PROT_READ | PROT_WRITE,
                                                       1, &bufioreq_pfn,
                                                       NULL);
        if ( *buffered_io_page == NULL )
        {
            ERROR("map buffered IO page returned error %d", errno);
            return -1;
        }
    }

    DEBUG("%d: buffered io evtchn is %x\n", __LINE__, bufioreq_evtchn);

    *bufioreq_remote_port = bufioreq_evtchn;

    return 0;
}


int main(int argc, char **argv)

{
    xc_interface *xc_handle;
    xc_dominfo_t domain_info;
    xendevicemodel_handle *dmod;
    xenforeignmemory_handle *fmem;
    xenevtchn_handle *xce;
    xenforeignmemory_resource_handle *fmem_resource;
    xen_pfn_t ioreq_gfn;
    xen_pfn_t bufioioreq_gfn;
    evtchn_port_t bufioreq_remote_port;
    shared_iopage_t *shared_page;
    buffered_iopage_t *buffered_io_page;
    int logfd;
    int domid;
    uint64_t ioreq_server_pages_cnt;
    size_t vcpu_count = 1;
    ioservid_t ioservid;
    char *logfile_name;
    int ret;
    int opt;
    int option_index = 0;
    int i;
    char c;

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

    logfile_name = malloc(VARSTORED_LOGFILE_MAX);
    memset(logfile_name, '\0', VARSTORED_LOGFILE_MAX);

    if ( argc == 1 )
    {
        printf(USAGE);
        exit(1);
    }

#warning "TODO: move this to after parsing and change the number from being getpid() to domid"
    ret = snprintf(logfile_name, VARSTORED_LOGFILE_MAX,  VARSTORED_LOGFILE, getpid());
    if ( ret < 0 )
    {
        ERROR("BUG: snprintf() error");
    }

    logfd = open(logfile_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if ( logfd < 0 )
    {
        ERROR("failed to open %s, err: %d, %s\n", logfile_name, errno, strerror(errno));
    }

    set_logfd(logfd);

    DEBUG("%d: Starting parsing args...\n", __LINE__);

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
            INFO("servicing UEFI variables for Domain %s\n", optarg);
            domid = atoi(optarg);
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
            UNIMPLEMENTED("pid");
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

#warning "TODO: implement signal handlers in order to tear down resources upon SIGKILL, etc..."

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
    ret = xc_domain_getinfo(xc_handle, domid, 1, &domain_info);
    if ( ret < 0 )
    {
        ret = errno;
        ERROR("Domid %u, xc_domain_getinfo error: %d, %s\n", domid, errno, strerror(errno));
        goto cleanup;
    }
    DEBUG("%d: xc_domain_getinfo()\n", __LINE__);

    /* Verify the requested domain == the returned domain */
    if ( domid != domain_info.domid )
    {
        ret = errno;
        ERROR("Domid %u does not match expected %u\n", domain_info.domid, domid);
        goto cleanup;
    }

    /* Retrieve IO req server page count, retry until available */
    for ( i=0; i<10; i++ )
    {
        ret = xc_hvm_param_get(xc_handle, domid, HVM_PARAM_NR_IOREQ_SERVER_PAGES, &ioreq_server_pages_cnt);
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
    dmod = xendevicemodel_open(0, 0);
    if ( !dmod )
    {
        ERROR("Failed to open xendevicemodel handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto cleanup;
    }

    /* Open xen foreign memory interface */
    fmem = xenforeignmemory_open(0, 0);
    if ( !fmem )
    {
        ERROR("Failed to open xenforeignmemory handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto close_dmod;
    }

    /* Open xen event channel */
    xce = xenevtchn_open(NULL, 0);
    if ( !xce )
    {
        ERROR("Failed to open evtchn handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto close_fmem;
    }

    /* Restrict varstored's privileged accesses */
    ret = xentoolcore_restrict_all(domid);
    if ( ret < 0 )
    {
        ERROR("Failed to restrict Xen handles: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto close_evtchn;
    }

    /* Create an IO Req server for Port IO requests in the port
     * range 0x100 to 0x103.  XenVariable in OVMF uses 0x100,
     * 0x101-0x103 are reserved.
     */
    ret = xendevicemodel_create_ioreq_server(dmod, domid,
                                             HVM_IOREQSRV_BUFIOREQ_LEGACY, &ioservid);
    if ( ret < 0 )
    {
        ERROR("Failed to create ioreq server: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto close_evtchn;
    }

    INFO("ioservid = %u\n", ioservid);

    ret = xen_map_ioreq_server(
            xc_handle, fmem, domid, ioservid, &shared_page,
            &buffered_io_page, &bufioreq_remote_port,
            &fmem_resource);
    if ( ret < 0 )
    {
        ERROR("Failed to map ioreq server: %d, %s\n", errno, strerror(errno));
        goto close_evtchn;
    }

    DEBUG("Mapped ioreq server\n");

    void *iopage = buffered_io_page + 0x400;
    INFO("shared_page = %p\n", shared_page);
    INFO("iopage = %p\n",iopage);
    INFO("buffered_io_page = %p\n", buffered_io_page);

    /* Enable the ioreq server state */
    ret = xendevicemodel_set_ioreq_server_state(dmod, domid, ioservid, 1);
    if ( ret < 0 )
    {
        ERROR("Failed to enable ioreq server: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto unmap_resource;
    }

    /* Setup memory to receive port IO RPC requests */
    INFO("%d vCPU(s)\n", vcpu_count);
    unsigned long *port_array = malloc(vcpu_count << 2);
    memset(port_array, 0xff, vcpu_count << 2);

    /* Bind the interdomain event channel */

    /* Initialize Port IO for domU */

    /* Check secure boot is enabled */

    /* Check enforcment level */

    /* Store the varserved pid in XenStore */

    /* Containerize varstored */

    /* Initialize UEFI variables */

    /* Initialize UEFI keys */

    /* Initialize event channel handler */
    INFO("Done!\n");
done:
    return 0;

unmap_resource:
    xenforeignmemory_unmap_resource(fmem, fmem_resource);

close_evtchn:
    xenevtchn_close(xce);

close_fmem:
    xenforeignmemory_close(fmem);

close_dmod:
    xendevicemodel_close(dmod);

cleanup:
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

