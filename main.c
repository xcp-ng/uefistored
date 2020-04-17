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

static inline int xen_get_ioreq_server_info(xc_interface *xc_handle,
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

    if ( !xc_handle )
    {
        ERROR("invalid NULL xc_handle ptr in %s\n", __func__);
        return -EINVAL;
    }

#if 0

    DEBUG("%s: domid=%d\n", __func__, dom);

    TRACE();
    rc = xc_hvm_param_get(xc_handle, dom, HVM_PARAM_IOREQ_PFN, &param);
    if ( rc < 0 )
    {
        ERROR("failed to get HVM_PARAM_IOREQ_PFN\n");
        return -1;
    }

    TRACE();
    *ioreq_pfn = param;

    TRACE();

    rc = xc_hvm_param_get(xc_handle, dom, HVM_PARAM_BUFIOREQ_PFN, &param);
    if ( rc < 0 )
    {
        ERROR("failed to get HVM_PARAM_BUFIOREQ_PFN\n");
        return -1;
    }
    TRACE();
    *bufioreq_pfn = param;

    TRACE();

    rc = xc_hvm_param_get(xc_handle, dom, HVM_PARAM_BUFIOREQ_EVTCHN,
                          &param);
    if ( rc < 0 )
    {
        ERROR("failed to get HVM_PARAM_BUFIOREQ_EVTCHN\n");
        return -1;
    }
    *bufioreq_evtchn = param;

    TRACE();
#endif

    return 0;
}

#define TARGET_PAGE_SIZE (1<<12)

static int xen_map_ioreq_server(
                                xenforeignmemory_handle *fmem,
                                domid_t domid,
                                ioservid_t ioservid,
                                shared_iopage_t **shared_page,
                                buffered_iopage_t **buffered_io_page,
                                xenforeignmemory_resource_handle **fres)
{
    void *addr = NULL;
    xen_pfn_t ioreq_pfn = 0;
    xen_pfn_t bufioreq_pfn = 0;
    xenforeignmemory_resource_handle *ret;

    if ( !fmem )
    {
        ERROR("Invalid NULL ptr for fmem\n");
        abort();
    }

    DEBUG("%s: %d\n", __func__, __LINE__);

    ret = xenforeignmemory_map_resource(fmem, domid,
                                        XENMEM_resource_ioreq_server,
                                        ioservid, 0, 2,
                                        &addr,
                                        PROT_READ | PROT_WRITE, 0);

    if ( !ret )
    {
        ERROR("failed to map ioreq server resources: error %d: %s",
                     errno, strerror(errno));
        return -1;
    }

    *fres = ret;
    *buffered_io_page = addr;
    *shared_page = addr + TARGET_PAGE_SIZE;

    return 0;
}

void (*_do_xfm_mamp)(long param_1,int param_2);
static xendevicemodel_handle *_dmod = NULL;
static xenforeignmemory_handle *_fmem = NULL;
static int _domid = -1;
static int some_static_var;
static ioservid_t _ioservid;
static unsigned long static_portio_port = 0x100;
static int DAT_0060d620;

void do_many_allocs_and_memcmp(int ret)
{
    (void) ret;
}

void do_xenforeignmemory_map(long param_1,int param_2)
{
    void *p;
    int ret;
    unsigned long array [16];

    if ( param_1 == 0 )
    {
        ret = 0;
        do {
            array[ret] = (unsigned long)(param_2 + ret);
            ret = ret + 1;
        } while ( ret != 0x10 );

        p = xenforeignmemory_map(_fmem, _domid, 3, 0x10, array,0);
        if ( p != 0 ) {
            do_many_allocs_and_memcmp(ret);
            xenforeignmemory_unmap(_fmem, p, 0x10);
            return;
        }
    }
    return;
}

int init_io_port(xendevicemodel_handle *dmod,
                 xenforeignmemory_handle *fmem,
                 int domid,
                 ioservid_t ioservid)
{
    int ret;
    _dmod = dmod;
    _fmem = fmem;
    _domid = domid;
    _ioservid = ioservid;

    if ( some_static_var == 0 )
    {
        _do_xfm_mamp = do_xenforeignmemory_map;
        DAT_0060d620 = 4;
        some_static_var = 1;
        static_portio_port = 0x100;
        ret = xendevicemodel_map_io_range_to_ioreq_server(dmod, domid, ioservid, 0, 0x100, 0x103);
        if ( ret < 0 )
        {
            ERROR("Failed to map io range to ioreq server: %d, %s\n", errno, strerror(errno));
            return ret;
        }
    }

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
    evtchn_port_t bufioreq_local_port;
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
            fmem, domid, ioservid, &shared_page,
            &buffered_io_page,
            &fmem_resource);
    if ( ret < 0 )
    {
        ERROR("Failed to map ioreq server: %d, %s\n", errno, strerror(errno));
        goto close_evtchn;
    }

    DEBUG("Mapped ioreq server\n");
    INFO("shared_page = %p\n", shared_page);
    INFO("buffered_io_page = %p\n", buffered_io_page);

    /* Enable the ioreq server state */
    ret = xendevicemodel_set_ioreq_server_state(dmod, domid, ioservid, 1);
    if ( ret < 0 )
    {
        ERROR("Failed to enable ioreq server: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto unmap_resource;
    }

    /* Bind the interdomain event channel */
    ret = xendevicemodel_get_ioreq_server_info(dmod, domid, ioservid, 0, 0, &bufioreq_remote_port);
    if ( ret < 0 )
    {
        ERROR("Failed to get ioreq server info: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto unmap_resource;
    }

    /* Initialize Port IO for domU */
    INFO("%d vCPU(s)\n", vcpu_count);
    size_t sz = vcpu_count * sizeof(unsigned long);
    unsigned long *port_array = malloc(sz);
    memset(port_array, 0xff, vcpu_count * sz);
    DEBUG("port_array=0x%x%x\n", port_array[0], port_array[1]);

    for ( i=0; i<vcpu_count; i++ )
    {
        ret = xenevtchn_bind_interdomain(xce, domid, shared_page->vcpu_ioreq[i].vp_eport);
        if ( ret < 0 )
        {
            ERROR("failed to bind evtchns: %d, %s\n", errno, strerror(errno));
            goto unmap_resource;
        }

        port_array[i] = ret;
    }

    for ( i=0; i<vcpu_count; i++ )
    {
        printf("VCPU%d: %u -> %u\n", i, port_array[i], shared_page->vcpu_ioreq[i].vp_eport);
    }

    ret = xenevtchn_bind_interdomain(xce, domid, bufioreq_remote_port);
    if ( ret < 0 )
    {
        ERROR("failed to bind evtchns: %d, %s\n", errno, strerror(errno));
        goto unmap_resource;
    }
    bufioreq_local_port = ret;

    ret = init_io_port(dmod, fmem, domid, ioservid);
    if ( ret < 0 )
    {
        ERROR("failed to init port io: %d\n", ret);
        goto unmap_resource;
    }

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
    free(logfile_name);
    return ret;
}

