#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <uchar.h>
#include <wchar.h>
#include <xenctrl.h>
#include <xenstore.h>
#include <xentoolcore.h>
#include <xendevicemodel.h>
#include <xenevtchn.h>
#include <xenforeignmemory.h>
#include <xen/hvm/dm_op.h>
#include <xen/hvm/ioreq.h>
#include <xen/hvm/params.h>
#include <xen/memory.h>

#include "common.h"
#include "config.h"
#include "log.h"
#include "storage.h"
#include "uefi/authlib.h"
#include "uefi/image_authentication.h"
#include "uefi/types.h"
#include "uefi/guids.h"
#include "backend.h"
#include "xen_variable_server.h"
#include "depriv.h"
#include "barrier.h"

#define IOREQ_BUFFER_SLOT_NUM 511 /* 8 bytes each, plus 2 4-byte indexes */

struct backend *backend = NULL;
struct backend xapidb;
static bool resume;

static xc_evtchn_port_or_error_t bufioreq_local_port;
static xc_evtchn_port_or_error_t *ioreq_local_ports;
static evtchn_port_t bufioreq_remote_port;
static xendevicemodel_handle *dmod;
static xenforeignmemory_handle *fmem;
static xenforeignmemory_resource_handle *fmem_resource;
static ioservid_t ioservid;
static xenevtchn_handle *xce;
static xc_interface *xc_handle;
struct xs_handle *xsh;

/* Options/args */
static unsigned int domid;
static bool depriv;
static uid_t uid;
static gid_t gid;
static char *root_path = NULL;
static char *pidfile;

extern bool secure_boot_enabled;
bool enforcement_level;

struct sigaction old_sighup;
struct sigaction old_sigint;
struct sigaction old_sigabrt;
struct sigaction old_sigterm;

static bool io_port_enabled;
static size_t io_port_size;
static xendevicemodel_handle *_dmod = NULL;
static xenforeignmemory_handle *_fmem = NULL;
static int _domid = -1;
static ioservid_t _ioservid;
static unsigned long io_port_addr;

#define UNUSED(var) ((void)var);

#define USAGE                                                                  \
    "Usage: uefistored <options> \n"                                           \
    "\n"                                                                       \
    "    --domain <domid> \n"                                                  \
    "    --resume \n"                                                          \
    "    --nonpersistent \n"                                                   \
    "    --depriv \n"                                                          \
    "    --uid <uid> \n"                                                       \
    "    --gid <gid> \n"                                                       \
    "    --chroot <chroot> \n"                                                 \
    "    --pidfile <pidfile> \n"                                               \
    "    --backend <backend> \n"                                               \
    "    --arg <name>:<val> \n\n"

#define UNIMPLEMENTED(opt) INFO(opt " option not implemented!\n")

#define DEFINE_AUTH_FILE(fname, _name, _guid, _attrs)                          \
    {                                                                          \
        .path = "/usr/share/uefistored/" fname,                                 \
        .var = {                                                               \
            .name = _name,                                                     \
            .namesz = sizeof_wchar(_name),                                           \
            .guid = _guid,                                                     \
            .attrs = _attrs,                                                   \
        },                                                                     \
    }

#define AT_ATTRS                                                               \
    EFI_VARIABLE_NON_VOLATILE |                                                \
            EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |               \
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS

struct auth_data auth_files[] = {
    DEFINE_AUTH_FILE("KEK.auth", L"KEK", EFI_GLOBAL_VARIABLE_GUID, AT_ATTRS),
    DEFINE_AUTH_FILE("db.auth", L"db", EFI_IMAGE_SECURITY_DATABASE_GUID, AT_ATTRS),
    DEFINE_AUTH_FILE("dbx.auth", L"dbx", EFI_IMAGE_SECURITY_DATABASE_GUID, AT_ATTRS),
    DEFINE_AUTH_FILE("PK.auth", L"PK", EFI_GLOBAL_VARIABLE_GUID, AT_ATTRS),
};

static int write_pidfile(void)
{
    int fd, ret;
    size_t len;
    char pidstr[21];

    if (!pidfile) {
        ERROR("No pidfile set\n");
        return -1;
    }

    ret = snprintf(pidstr, sizeof(pidstr), "%u", getpid());

    if (ret < 0) {
        ERROR("pidstr snprintf failed\n");
        return -1;
    }

    len = (size_t)ret;

    fd = open(pidfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

    if (fd < 0) {
        ERROR("Could not open pidfile: %s, %s\n", pidfile, strerror(errno));
        return -1;
    }

    if (write(fd, pidstr, len) < 0) {
        ERROR("Failed to write pidfile\n");
        ret = -1;
        goto done;
    }

    ret = 0;

done:
    close(fd);
    return ret;
}

static int xen_map_ioreq_server(xenforeignmemory_handle *fmem, domid_t domid,
                                ioservid_t ioservid,
                                shared_iopage_t **shared_iopage,
                                buffered_iopage_t **buffered_iopage,
                                xenforeignmemory_resource_handle **fresp)
{
    void *addr = NULL;
    xenforeignmemory_resource_handle *fres;

    if (!fmem) {
        ERROR("Invalid NULL ptr for fmem\n");
        abort();
    }

    fres = xenforeignmemory_map_resource(fmem, domid,
                                         XENMEM_resource_ioreq_server, ioservid,
                                         0, 2, &addr, PROT_READ | PROT_WRITE,
                                         0);

    if (!fres) {
        ERROR("failed to map ioreq server resources: error %d: %s", errno,
              strerror(errno));
        return -1;
    }

    *fresp = fres;
    *buffered_iopage = addr;
    *shared_iopage = addr + PAGE_SIZE;

    return 0;
}

static int setup_portio(xendevicemodel_handle *dmod,
                        xenforeignmemory_handle *fmem, int domid,
                        ioservid_t ioservid)
{
    int ret;

    _dmod = dmod;
    _fmem = fmem;
    _domid = domid;
    _ioservid = ioservid;

    if (io_port_enabled) {
        ERROR("Cannot initialize an already enabled ioport!\n");
        return -1;
    }

    io_port_size = 4;
    io_port_enabled = true;
    io_port_addr = 0x100;

    ret = xendevicemodel_map_io_range_to_ioreq_server(
            dmod, domid, ioservid, 0, io_port_addr,
            io_port_addr + io_port_size - 1);

    if (ret < 0) {
        ERROR("Failed to map io range to ioreq server: %d, %s\n", errno,
              strerror(errno));
        return ret;
    }

    INFO("map IO port: 0x%02lx - 0x%02lx\n", io_port_addr,
         io_port_addr + io_port_size - 1);
    return 0;
}

static bool uefistored_xs_read_bool(struct xs_handle *xsh, const char *xs_path,
                                    int domid)
{
    char buf[128];
    char *data;
    unsigned int len;
    bool ret;

    snprintf(buf, sizeof(buf), xs_path, domid);
    data = xs_read(xsh, XBT_NULL, buf, &len);

    if (!data)
        return false;

    ret = !strncmp(data, "true", len);

    free(data);

    return ret;
}

/**
 * map_guest_memory - Map in pages from the guest address space
 *
 * Map the GFNs from start to (start + SHMEM_PAGES) from guest space to uefistored
 * as shared memory.
 */
static void *map_guest_memory(xen_pfn_t start)
{
    int i;
    xen_pfn_t shmem[SHMEM_PAGES];

    for (i = 0; i < SHMEM_PAGES; i++) {
        shmem[i] = start + i;
    }

    return xenforeignmemory_map(_fmem, _domid, PROT_READ | PROT_WRITE,
                                SHMEM_PAGES, shmem, NULL);
}

void handle_ioreq(struct ioreq *ioreq)
{
    void *shmem;
    uint64_t port_addr = ioreq->addr;
    uint64_t gfn = ioreq->data;
    uint32_t size = ioreq->size;

    if (!io_port_enabled) {
        ERROR("ioport not yet enabled!\n");
        return;
    }

    if (!(io_port_addr <= port_addr &&
          port_addr < io_port_addr + io_port_size)) {
        ERROR("port addr 0x%lx not in range (0x%02lx-0x%02lx)\n", port_addr,
              io_port_addr, io_port_addr + io_port_size - 1);
        return;
    }

    if (size != 4) {
        ERROR("Expected size 4, got %u\n", size);
        return;
    }

    if (ioreq->type != IOREQ_TYPE_PIO) {
        return;
    }

    shmem = map_guest_memory(gfn);

    if (!shmem) {
        ERROR("failed to map guest memory!\n");
        return;
    }

    /* Now that we have mapped in the XenVariable command, let's process it. */
    smp_mb();
    xen_variable_server_handle_request(shmem);
    smp_mb();

    /* Free up mappable space */
    xenforeignmemory_unmap(_fmem, shmem, SHMEM_PAGES);
}

static void handle_shared_iopage(shared_iopage_t *shared_iopage,
                                 evtchn_port_t port, size_t vcpu)
{
    struct ioreq *ioreq;

    if (!shared_iopage) {
        ERROR("null sharedio_page\n");
        return;
    }

    ioreq = &shared_iopage->vcpu_ioreq[vcpu];

    if (ioreq->state != STATE_IOREQ_READY) {
        /*
         * This often happens shortly after initializing the ioreq server.
         * Just return -1 and let the caller try again.
         */
        INFO("IO request not ready\n");
        return;
    }

    barrier();
    ioreq->state = STATE_IOREQ_INPROCESS;

    handle_ioreq(ioreq);
    barrier();

    ioreq->state = STATE_IORESP_READY;
    barrier();

    xenevtchn_notify(xce, port);
}

static void poll_buffered_iopage(buffered_iopage_t *buffered_iopage)
{
    for (;;) {
        unsigned int read_pointer;
        unsigned int write_pointer;

        read_pointer = buffered_iopage->read_pointer;
        write_pointer = buffered_iopage->write_pointer;

        if (read_pointer == write_pointer)
            break;

        while (read_pointer != write_pointer) {
            unsigned int slot;
            buf_ioreq_t *buf_ioreq;
            ioreq_t ioreq;

            slot = read_pointer % IOREQ_BUFFER_SLOT_NUM;

            buf_ioreq = &buffered_iopage->buf_ioreq[slot];

            ioreq.size = 1UL << buf_ioreq->size;
            ioreq.count = 1;
            ioreq.addr = buf_ioreq->addr;
            ioreq.data = buf_ioreq->data;
            ioreq.state = STATE_IOREQ_READY;
            ioreq.dir = buf_ioreq->dir;
            ioreq.df = 1;
            ioreq.type = buf_ioreq->type;
            ioreq.data_is_ptr = 0;

            read_pointer++;

            if (ioreq.size == 8) {
                slot = read_pointer % IOREQ_BUFFER_SLOT_NUM;
                buf_ioreq = &buffered_iopage->buf_ioreq[slot];

                ioreq.data |= ((uint64_t)buf_ioreq->data) << 32;

                read_pointer++;
            }

            handle_ioreq(&ioreq);
            barrier();
        }

        buffered_iopage->read_pointer = read_pointer;
        barrier();
    }
}

static void signal_handler(int sig)
{
    INFO("uefistored received signal: %s\n", strsignal(sig));


    backend_set();
    backend_save();
    storage_destroy();

    if (fmem && fmem_resource)
        xenforeignmemory_unmap_resource(fmem, fmem_resource);

    if (xce) {
        xenevtchn_unbind(xce, bufioreq_local_port);
        xenevtchn_close(xce);
    }

    if (fmem)
        xenforeignmemory_close(fmem);

    if (dmod) {
        xendevicemodel_set_ioreq_server_state(dmod, (uint64_t)domid,
                                              (uint64_t)ioservid, 0);
        xendevicemodel_destroy_ioreq_server(dmod, (uint64_t)domid,
                                            (uint64_t)ioservid);
        xendevicemodel_close(dmod);
    }

    if (xc_handle)
        xc_interface_close(xc_handle);

    if (root_path)
        free(root_path);

    if (pidfile)
        free(pidfile);

    backend_cleanup();

    signal(sig, SIG_DFL);
    raise(sig);
    exit(0);
}

static struct sigaction *get_old(int sig)
{
    switch (sig) {
    case SIGHUP:
        return &old_sighup;
    case SIGINT:
        return &old_sigint;
    case SIGABRT:
        return &old_sigabrt;
    case SIGTERM:
        return &old_sigterm;
    }

    return NULL;
}

static int install_sighandler(int sig)
{
    int ret;
    struct sigaction new;

    new.sa_handler = signal_handler;
    sigemptyset(&new.sa_mask);
    new.sa_flags = 0;

    ret = sigaction(sig, &new, get_old(sig));
    if (ret < 0) {
        ERROR("Failed to set SIGKILL handler\n");
    }

    return ret;
}

static int install_sighandlers(void)
{
    int ret;

    ret = install_sighandler(SIGINT);
    if (ret < 0)
        return ret;

    ret = install_sighandler(SIGABRT);
    if (ret < 0)
        return ret;

    ret = install_sighandler(SIGTERM);
    if (ret < 0)
        return ret;

    ret = install_sighandler(SIGHUP);
    if (ret < 0)
        return ret;

    return ret;
}

static void printargs(int argc, char **argv)
{
    int i;

    (void)argv;

    DPRINTF("\nargs: ");
    for (i = 0; i < argc; i++) {
        DPRINTF("%s ", argv[i]);
    }
    DPRINTF("\n");
}

/*
 * Store the uefistored pid in XenStore to signal to XAPI that uefistored is alive
 */
static int write_pid(void)
{
    char pidstr[21];
    char pidalive[0x80];
    int ret;

    if (snprintf(pidalive, sizeof(pidalive), "/local/domain/%u/varstored-pid",
                 domid) < 0) {
        ERROR("buffer error: %d, %s\n", errno, strerror(errno));
        return -1;
    }

    if ((ret = snprintf(pidstr, sizeof(pidstr), "%u", getpid()) < 0)) {
        ERROR("pidstr asprintf failed\n");
        return -1;
    }

    if (xs_write(xsh, XBT_NULL, pidalive, pidstr, ret) == false) {
        ERROR("xs_write failed: %d, %s\n", errno, strerror(errno));
        return -1;
    }

    return 0;
}

void handler_loop(buffered_iopage_t *buffered_iopage, size_t vcpu_count,
                  shared_iopage_t *shared_iopage)
{
    size_t i;
    int ret;
    struct pollfd pollfd;
    xc_evtchn_port_or_error_t port;

    pollfd.fd = xenevtchn_fd(xce);
    pollfd.events = POLLIN | POLLERR | POLLHUP;
    pollfd.revents = 0;

    while (true) {
        ret = poll(&pollfd, 1, 5000);

        if (ret < 0 && errno != EINTR) {
            exit(1);
        }

        if (ret <= 0 || !(pollfd.revents & POLLIN)) {
            continue;
        }

        port = xenevtchn_pending(xce);

        if (port == bufioreq_local_port) {
            xenevtchn_unmask(xce, port);
            poll_buffered_iopage(buffered_iopage);
        } else {
            for (i = 0; i < vcpu_count; i++) {
                xenevtchn_unmask(xce, port);
                if (ioreq_local_ports[i] == port) {
                    handle_shared_iopage(shared_iopage, port, i);
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    xc_dominfo_t domain_info;
    shared_iopage_t *shared_iopage;
    buffered_iopage_t *buffered_iopage;
    uint64_t ioreq_server_pages_cnt;
    size_t vcpu_count = 1;
    int ret;
    int option_index = 0;
    size_t i;
    char c;
    EFI_STATUS status;
    char *end;

    const struct option options[] = {
        { "domain", required_argument, 0, 'd' },
        { "resume", no_argument, 0, 'r' },
        { "nonpersistent", no_argument, 0, 'n' },
        { "depriv", no_argument, 0, 'p' },
        { "uid", required_argument, 0, 'u' },
        { "gid", required_argument, 0, 'g' },
        { "chroot", required_argument, 0, 'c' },
        { "pidfile", required_argument, 0, 'i' },
        { "backend", required_argument, 0, 'b' },
        { "arg", required_argument, 0, 'a' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 },
    };

    if (argc == 1) {
        printf(USAGE);
        exit(1);
    }

    install_sighandlers();

    while (1) {
        c = getopt_long(argc, argv, "d:rnpu:g:c:i:b:ha:", options,
                        &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (options[option_index].flag != 0)
                break;

            printf("option %s", options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;

        case 'd':
            if (optarg)
                domid = atoi(optarg);
            break;

        case 'r':
            resume = true;
            break;

        case 'n':
            UNIMPLEMENTED("nonpersistent");
            break;

        case 'p':
            depriv = true;
            break;

        case 'u':
            if (optarg) {
                uid = (uid_t)strtol(optarg, &end, 0);

                if (*end != '\0') {
                    fprintf(stderr, "invalid uid '%s'\n", optarg);
                    exit(1);
                }
            }
            break;

        case 'g':
            if (optarg) {
                gid = (gid_t)strtol(optarg, &end, 0);
                if (*end != '\0') {
                    fprintf(stderr, "invalid uid '%s'\n", optarg);
                    exit(1);
                }
            }
            break;

        case 'c':
            root_path = strdup(optarg);
            break;

        case 'i':
            pidfile = strdup(optarg);
            break;

        case 'b':
            /* We currently only support the xapidb backend */
            if (!strcmp(optarg, "xapidb")) {
                backend = &xapidb;
            } else {
                fprintf(stderr, "Invalid backend '%s'\n", optarg);
                fprintf(stderr, USAGE);
            }
            break;

        case 'a': {
            if (backend_parse_arg(optarg) < 0)
                exit(1);
            break;
        }

        case 'h':
        case '?':
        default:
            fprintf(stderr, USAGE);
            exit(1);
        }
    }

    printargs(argc, argv);

    if (!root_path)
        ERROR("No root path\n");

    /* Gain access to the hypervisor */
    xc_handle = xc_interface_open(NULL, NULL, 0);

    if (!xc_handle) {
        ERROR("Failed to open xc_interface handle: %d, %s\n", errno,
              strerror(errno));
        goto err;
    }

    /* Get info on the domain */
    ret = xc_domain_getinfo(xc_handle, domid, 1, &domain_info);

    if (ret < 0) {
        ERROR("Domid %u, xc_domain_getinfo error: %d, %s\n", domid, errno,
              strerror(errno));
        goto err;
    }

    vcpu_count = domain_info.max_vcpu_id + 1;

    /* Verify the requested domain == the returned domain */
    if (domid != domain_info.domid) {
        ERROR("Domid %u does not match expected %u\n", domain_info.domid,
              domid);
        goto err;
    }

    /* Retrieve IO req server page count, retry until available */
    for (i = 0; i < 10; i++) {
        ret = xc_hvm_param_get(xc_handle, domid,
                               HVM_PARAM_NR_IOREQ_SERVER_PAGES,
                               &ioreq_server_pages_cnt);
        if (ret < 0) {
            ERROR("xc_hvm_param_get failed: %d, %s\n", errno, strerror(errno));
            goto err;
        }

        if (ioreq_server_pages_cnt != 0)
            break;

        printf("Waiting for ioreq server");
        usleep(100000);
    }
    INFO("HVM_PARAM_NR_IOREQ_SERVER_PAGES = %ld\n", ioreq_server_pages_cnt);

    xc_interface_close(xc_handle);
    xc_handle = NULL;

    /* Open xen device model */
    dmod = xendevicemodel_open(NULL, 0);

    if (!dmod) {
        ERROR("Failed to open xendevicemodel handle: %d, %s\n", errno,
              strerror(errno));
        goto err;
    }

    /* Open xen foreign memory interface */
    fmem = xenforeignmemory_open(NULL, 0);

    if (!fmem) {
        ERROR("Failed to open xenforeignmemory handle: %d, %s\n", errno,
              strerror(errno));
        goto err;
    }

    /* Open xen event channel */
    xce = xenevtchn_open(NULL, 0);

    if (!xce) {
        ERROR("Failed to open evtchn handle: %d, %s\n", errno, strerror(errno));
        goto err;
    }

    /* Restrict uefistored's privileged accesses */
    ret = xentoolcore_restrict_all(domid);

    if (ret < 0) {
        ERROR("Failed to restrict Xen handles: %d, %s\n", errno,
              strerror(errno));
        goto err;
    }

    /* Create an IO Req server for Port IO requests in the port
     * range 0x100 to 0x103.  XenVariable in OVMF uses 0x100,
     * 0x101-0x103 are reserved.
     */
    ret = xendevicemodel_create_ioreq_server(
            dmod, domid, HVM_IOREQSRV_BUFIOREQ_LEGACY, &ioservid);

    if (ret < 0) {
        ERROR("Failed to create ioreq server: %d, %s\n", errno,
              strerror(errno));
        goto err;
    }

    ret = xen_map_ioreq_server(fmem, domid, ioservid, &shared_iopage,
                               &buffered_iopage, &fmem_resource);

    if (ret < 0) {
        ERROR("Failed to map ioreq server: %d, %s\n", errno, strerror(errno));
        goto err;
    }

    ret = xendevicemodel_get_ioreq_server_info(dmod, domid, ioservid, NULL,
                                               NULL, &bufioreq_remote_port);
    if (ret < 0) {
        ERROR("Failed to get ioreq server info: %d, %s\n", errno,
              strerror(errno));
        goto err;
    }

    /* Enable the ioreq server state */
    ret = xendevicemodel_set_ioreq_server_state(dmod, domid, ioservid, 1);

    if (ret < 0) {
        ERROR("Failed to enable ioreq server: %d, %s\n", errno,
              strerror(errno));
        goto err;
    }

    /* Initialize Port IO for domU */
    INFO("%lu vCPU(s)\n", vcpu_count);
    ioreq_local_ports = malloc(sizeof(xc_evtchn_port_or_error_t) * vcpu_count);

    if (!ioreq_local_ports) {
        ERROR("Failed to alloc ioreq_local_ports\n");
        goto err;
    }

    for (i = 0; i < vcpu_count; i++) {
        ret = xenevtchn_bind_interdomain(xce, domid,
                                         shared_iopage->vcpu_ioreq[i].vp_eport);
        if (ret < 0) {
            ERROR("failed to bind evtchns: %d, %s\n", errno, strerror(errno));
            goto err;
        }

        ioreq_local_ports[i] = ret;

        INFO("VCPU%lu: %u -> %u\n", i, ioreq_local_ports[i],
             shared_iopage->vcpu_ioreq[i].vp_eport);
    }

    ret = xenevtchn_bind_interdomain(xce, domid, bufioreq_remote_port);
    if (ret < 0) {
        ERROR("failed to bind evtchns: %d, %s\n", errno, strerror(errno));
        goto err;
    }

    bufioreq_local_port = ret;

    ret = setup_portio(dmod, fmem, domid, ioservid);
    if (ret < 0) {
        ERROR("failed to init port io: %d\n", ret);
        goto err;
    }

    xsh = xs_open(0);
    if (!xsh) {
        ERROR("Couldn't open xenstore: %d, %s", errno, strerror(errno));
        goto err;
    }

    /* Check secure boot is enabled */
    secure_boot_enabled = uefistored_xs_read_bool(
            xsh, "/local/domain/%u/platform/secureboot", domid);
    INFO("Secure boot enabled: %s\n", secure_boot_enabled ? "true" : "false");

    /* Check enforcment level */
    enforcement_level = uefistored_xs_read_bool(
            xsh, "/local/domain/%u/platform/auth-enforce", domid);
    INFO("Authenticated variables: %s\n",
         enforcement_level ? "enforcing" : "permissive");

    if (write_pidfile() < 0) {
        ERROR("failed to write pidfile\n");
        goto err;
    }

    storage_init();

    auth_lib_load(auth_files, ARRAY_SIZE(auth_files));

    if (!drop_privileges(root_path, depriv, gid, uid)) {
        goto err;
    }


    if (backend_init(resume) < 0) {
        goto err;
    }

    status = auth_lib_initialize(auth_files, ARRAY_SIZE(auth_files));

    if (status != EFI_SUCCESS) {
        ERROR("auth_lib_initialization() failed, status=%s (0x%lx)",
              efi_status_str(status), status);

        assert(status == EFI_SUCCESS);
    }

    if (write_pid() < 0)
        goto err;

    handler_loop(buffered_iopage, vcpu_count, shared_iopage);

err:
    ERROR("Did not enter loop! dying...\n");
    exit(1);
    return -1;
}
