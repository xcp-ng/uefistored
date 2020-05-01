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
#include <uchar.h>

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

#include "backends/mem.h"
#include "common.h"
#include "parse.h"

#define IOREQ_SERVER_TYPE 0
#define IOREQ_SERVER_FRAME_NR 2

#define VARSTORED_LOGFILE "/var/log/varstored-%d.log"
#define VARSTORED_LOGFILE_MAX 32
#define IOREQ_BUFFER_SLOT_NUM     511 /* 8 bytes each, plus 2 4-byte indexes */

void handle_bufioreq(buf_ioreq_t *buf_ioreq);
int handle_shared_iopage(xenevtchn_handle *xce, shared_iopage_t *shared_iopage, evtchn_port_t port, size_t vcpu);

char assertsz[sizeof(unsigned long) == sizeof(xen_pfn_t)] = {0};

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

static inline int xen_get_ioreq_server_info(xc_interface *xc_handle,
                                            domid_t dom,
                                            xen_pfn_t *ioreq_pfn,
                                            xen_pfn_t *bufioreq_pfn,
                                            evtchn_port_t *bufioreq_evtchn)
{
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
                                shared_iopage_t **shared_iopage,
                                buffered_iopage_t **buffered_iopage,
                                xenforeignmemory_resource_handle **fresp)
{
    void *addr = NULL;
    xenforeignmemory_resource_handle *fres;

    if ( !fmem )
    {
        ERROR("Invalid NULL ptr for fmem\n");
        abort();
    }

    fres = xenforeignmemory_map_resource(fmem, domid,
                                        XENMEM_resource_ioreq_server,
                                        ioservid, 0, 2,
                                        &addr,
                                        PROT_READ | PROT_WRITE, 0);

    if ( !fres )
    {
        ERROR("failed to map ioreq server resources: error %d: %s",
                     errno, strerror(errno));
        return -1;
    }

    *fresp = fres;
    *buffered_iopage = addr;
    *shared_iopage = addr + TARGET_PAGE_SIZE;

    DEBUG("fresp=%p, buffered_iopage=%p, shared_iopage=%p\n",
            fresp,
            buffered_iopage,
            shared_iopage);
    return 0;
}

static bool io_port_enabled;
static size_t io_port_size;
static xendevicemodel_handle *_dmod = NULL;
static xenforeignmemory_handle *_fmem = NULL;
static int _domid = -1;
static ioservid_t _ioservid;
static unsigned long io_port_addr;

/* UEFI Definitions */
typedef uint64_t EFI_STATUS;

#define EFI_SUCCESS 0
#define EFI_NOT_FOUND 14


#define VARIABLE_NAME_SZ_OFFSET 8
#define VARIABLE_NAME_OFFSET 16

#define VARIABLE_GUID_OFFSET(shared_page) \
    ((variable_name_len(shared_page)) + VARIABLE_NAME_OFFSET)

#define VARIABLE_DATASIZE_OFFSET(shared_page) \
    VARIABLE_GUID_OFFSET(shared_page) + 16

#define VARIABLE_DATA_OFFSET(shared_page) \
    (VARIABLE_DATASIZE_OFFSET(shared_page) + 8)

#define COMMAND_OFFSET 4


#define SET_VAR_VENDOR_GUID_OFFSET 16

static bool get_next_initialized = false;

typedef struct {
    uint32_t  data1;
    uint16_t  data2;
    uint16_t  data3;
    uint8_t   data4[8];
} efi_guid_t;


struct req_header {
    uint32_t version;
    uint32_t command_type;
};


static inline uint64_t variable_name_sz(void *shared_page)
{
    return *((uint64_t *) (shared_page + VARIABLE_NAME_SZ_OFFSET));
}

static inline char16_t *variable_name(void *shared_page)
{
    return (char16_t *)(shared_page + VARIABLE_NAME_OFFSET);
}

static inline size_t variable_name_len(void *shared_page)
{
    return variable_name_sz(shared_page) / sizeof(char16_t);
}

static uint64_t variable_datalen(void *shared_page)
{
    size_t off =
        COMMAND_OFFSET + VARIABLE_NAME_OFFSET + 
        variable_name_len(shared_page) + 
        SET_VAR_VENDOR_GUID_OFFSET - 1;
    return *((uint64_t*)(shared_page + off));
}

static void* variable_data(void *shared_page)
{
    return shared_page + VARIABLE_DATA_OFFSET(shared_page);
}

static char strbuf[512];

/**
 * dprint_vname -  Debug print a variable name
 *
 * WARNING: this only prints ASCII characters correctly.
 * Any char code above 255 will be displayed incorrectly.
 */
void dprint_vname(char16_t *vn, uint64_t vnlen)
{
    int i;

    for (i=0; i<vnlen; i++)
    {
        strbuf[i] = (char)(vn[i] & 0xff);
    }

    DEBUG("name (%lu): %s\n", vnlen, strbuf);

    memset(strbuf, '\0', 512);
}

void handle_uefi_get_variable(void *shared_page)
{
    size_t len;
    int ret;
    void *val;
    const uint64_t vnlen = variable_name_len(shared_page);
    char16_t *vn = variable_name(shared_page);

    dprint_vname(vn, vnlen);
    DEBUG("cmd:GET_VARIABLE\n");

    ret = db_get((void*) vn, vnlen*2, &val, &len);
    if ( ret < 0 )
    {
        ERROR("Failed to get variable\n");
        return;
    }

    DEBUG("End GET_VARIABLE\n");
}

void handle_uefi_set_variable(void *shared_page)
{
    void *data = variable_data(shared_page);
    uint64_t datalen = variable_datalen(shared_page);
    int ret;
    char16_t *vn = variable_name(shared_page);
    const uint64_t vnlen = variable_name_len(shared_page);

    dprint_vname(vn, vnlen);
    DEBUG("cmd:SET_VARIABLE\n");

    DEBUG("shared_page=%p, data=%p\n", shared_page, data);
    DEBUG("datalen=0x%lx\n", datalen);
    ret = db_set((void*) vn, vnlen, data, datalen);
    if ( ret < 0 )
    {
        ERROR("Failed to set variable in db\n");
        return;
    }
}


void handle_uefi_get_next_variable(void *shared_page)
{
    const uint64_t vnlen = variable_name_len(shared_page);
    char16_t *vn = variable_name(shared_page);
    EFI_STATUS rc;

    DEBUG("cmd:GET_NEXT_VARIABLE\n");
    DEBUG("vnlen: %lu\n", vnlen);

    /**
     * To start the search, a Null-terminated string is passed in
     * VariableName; that is, VariableName is a pointer to a Null character.
     * This is always done on the initial call to GetNextVariableName().
     */

    if ( (!get_next_initialized) && (*variable_name) != ((char16_t) '\0') )
    {
        /* TODO: Does this make sense ? */
        rc = EFI_NOT_FOUND;
    }
    else
    {
        rc = EFI_SUCCESS;
    }

    get_next_initialized = 1;
    *((EFI_STATUS *) shared_page) = rc;
}

void handle_uefi_var_request(void *shared_page)
{
    struct req_header *hdr = shared_page;

    DEBUG("version=%u\n", hdr->version);

#if 1
    int i;
    DPRINTF("MESSAGE: ");
    for (i=0; i<0x38; i++)
    {
        DPRINTF("0x%x ", *((uint8_t*)(shared_page + i)));
    }
    DPRINTF("\n");
#endif

    switch ( hdr->command_type )
    {
        case COMMAND_GET_VARIABLE:
            handle_uefi_get_variable(shared_page);
            break;
        case COMMAND_SET_VARIABLE:
            handle_uefi_set_variable(shared_page);
            break;
        case COMMAND_GET_NEXT_VARIABLE:
            handle_uefi_get_next_variable(shared_page);
            break;
        case COMMAND_QUERY_VARIABLE_INFO:
            DEBUG("cmd:QUERY_VARIABLE_VARIABLE\n");
            break;
        case COMMAND_NOTIFY_SB_FAILURE:
            DEBUG("cmd:NOTIFY_SB_FAILURE\n");
            break;
        default:
            ERROR("cmd: unknown: 0x%x\n", hdr->command_type);
            break;
    }
}

/* OVMF XenVariable loads 16 pages of shared memory to pass varstored the command */
#define SHMEM_PAGES 16

/**
 * map_guest_memory - Map in a page from the guest address space
 *
 * Map the GFNs from start to (start + SHMEM_PAGES) from guest space to varstored
 * as shared memory.
 */
void *map_guest_memory(xen_pfn_t start)
{
    int i;
    xen_pfn_t shmem[SHMEM_PAGES];
        
    for ( i=0; i<SHMEM_PAGES; i++ )
    {
        shmem[i] = start + i;
    }

    DEBUG("Attempting to map in: 0x%02lx-0x%02lx\n", start, start + i);
    return xenforeignmemory_map(_fmem, _domid, PROT_READ | PROT_WRITE, 16, shmem, NULL);
}

void handle_ioreq(struct ioreq *ioreq)

{
    void *p;

    /* The port number is the ioreq address. */
    uint64_t port_addr = ioreq->addr;

    /*
     * The data written to the port is actually the GFN of the XenVariable command.
     *
     * See relevant XenVariable here:
     *  https://github.com/xcp-ng-rpms/edk2/blob/bd307ee95ceddc8edcaafd212ee5416ae7d8a0c9/SOURCES/add-xen-variable.patch#L204
     */
    uint64_t gfn = ioreq->data;

    /* This is just the size of the port write.  We only use it to require XenVariable to use 32bit port IO writes. */
    uint32_t size = ioreq->size;

    DEBUG("%s, ioreq: addr=0x%lx,data=0x%lx, count=0x%x, size=0x%x, vp_eport=0x%x, state=0x%x\n, data_is_ptr=%d, dir=%d, type=0x%x\n",
            __func__,
            ioreq->addr, ioreq->data, ioreq->count, ioreq->size,
            ioreq->vp_eport, ioreq->state, ioreq->data_is_ptr, ioreq->dir, ioreq->type);

    if ( !io_port_enabled )
    {
        ERROR("ioport not yet enabled!\n");
        return;
    }

    if ( !(io_port_addr <= port_addr && port_addr < io_port_addr + io_port_size) )
    {
        ERROR("port addr 0x%lx not in range (0x%02lx-0x%02lx)\n",
                port_addr, io_port_addr, io_port_addr + io_port_size - 1);
        return;
    }

    if ( size != 4 )
    {
        ERROR("Expected size 4, got %u\n", size);
        return;
    }
        
    p = map_guest_memory(gfn);
    if ( p )
    {
        /* Now that we have mapped in the UEFI Variables Service command from XenVariable,
         * let's process it. */
        handle_uefi_var_request(p);

        /* Free up mappable space */
        xenforeignmemory_unmap(_fmem, p, 16);
    }
}

void handle_pio(xenevtchn_handle *xce, evtchn_port_t port, struct ioreq *ioreq)
{
    if ( ioreq->type > 8 )
    {
        ERROR("UNKNOWN (%02x)", ioreq->type);
        return;
    }

    if ( ioreq->type != IOREQ_TYPE_PIO )
    {
        ERROR("Not PIO ioreq type, 0x%02x\n", ioreq->type);
        return;
    }

    assert( ioreq->state < 16 );

    DEBUG("ioreq: addr=0x%lx,data=0x%lx, count=0x%x, size=0x%x, vp_eport=0x%x, state=0x%x\n, data_is_ptr=%d, dir=%d, type=0x%x\n",
            ioreq->addr, ioreq->data, ioreq->count, ioreq->size,
            ioreq->vp_eport, ioreq->state, ioreq->data_is_ptr, ioreq->dir, ioreq->type);

    if ( ioreq->state != STATE_IOREQ_READY )
    {
        ERROR("IO request not ready\n");
        return;
    }

    ioreq->state = STATE_IOREQ_INPROCESS;
    handle_ioreq(ioreq);
    ioreq->state = STATE_IORESP_READY;
    xenevtchn_notify(xce, port);
}

int setup_portio(xendevicemodel_handle *dmod,
                 xenforeignmemory_handle *fmem,
                 int domid,
                 ioservid_t ioservid)
{
    _dmod = dmod;
    _fmem = fmem;
    _domid = domid;
    _ioservid = ioservid;
    int ret;

    if ( io_port_enabled )
    {
        ERROR("Cannot initialize an already enabled ioport!\n");
        return -1;
    }

    io_port_size = 4;
    io_port_enabled = true;
    io_port_addr = 0x100;
    ret = xendevicemodel_map_io_range_to_ioreq_server(dmod, domid, ioservid,
                                                      0, io_port_addr,
                                                      io_port_addr + io_port_size - 1);
    if ( ret < 0 )
    {
        ERROR("Failed to map io range to ioreq server: %d, %s\n", errno, strerror(errno));
        return ret;
    }

    INFO("map IO port: 0x%02lx - 0x%02lx\n", io_port_addr, io_port_addr + io_port_size - 1);
    return 0;
}

#define AUTH_FILE "/auth/file/path/"
#define MB(x) (x << 20)

static void *auth_file;

int load_auth_file(void)
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
            ERROR("Auth file %s is missing!\n", AUTH_FILE);
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

char *varstored_xs_read_string(struct xs_handle *xsh, const char *xs_path, int domid, unsigned int *len)
{
    char stringbuf[0x80];

    snprintf(stringbuf, sizeof(stringbuf), xs_path, domid);
    return xs_read(xsh, XBT_NULL, stringbuf, len);
}

bool varstored_xs_read_bool(struct xs_handle *xsh, const char *xs_path, int domid)
{
    char *data;
    unsigned int len;

    data = varstored_xs_read_string(xsh, xs_path, domid, &len);
    if ( !data )
        return false;

    return strncmp(data, "true", len) == 0;
}

void handler_loop(xenevtchn_handle *xce,
        buffered_iopage_t *buffered_iopage,
        evtchn_port_t bufioreq_local_port,
        evtchn_port_t *remote_vcpu_ports,
        int vcpu_count,
        shared_iopage_t *shared_iopage)
{
    size_t i;
    int ret;
    struct pollfd pollfd;
    evtchn_port_t port;

    pollfd.fd = xenevtchn_fd(xce);
    pollfd.events = POLLIN | POLLERR | POLLHUP;

    DEBUG("bufioreq_local_port=%d\n", bufioreq_local_port);

    while ( true )
    {
        ret = poll(&pollfd, 1, -1);
        if ( ret < 0 )
        {
            ERROR("poll error on fd %d: %d, %s\n", pollfd.fd, errno, strerror(errno));
            usleep(100000);
            continue;
        }

        port = xenevtchn_pending(xce);
        if ( port < 0 )
        {
            ERROR("xenevtchn_pending() error: %d, %s\n", errno, strerror(errno));
            continue;
        }

        ret = xenevtchn_unmask(xce, port);
        if ( ret < 0 )
        {
            ERROR("xenevtchn_unmask() error: %d, %s\n", errno, strerror(errno));
            continue;
        }

        if ( port == bufioreq_local_port )
        {

            int i;
            buf_ioreq_t *p;

            for ( i=0; i<IOREQ_BUFFER_SLOT_NUM; i++ ) 
            {
                p = &buffered_iopage->buf_ioreq[i];

                /* Do some thing */
                handle_bufioreq(p);
            }
        }
        else
        {
            for ( i=0; i<vcpu_count; i++ )
            {
                evtchn_port_t remote_port = remote_vcpu_ports[i];
                if ( remote_port == port )
                {
                    ret = handle_shared_iopage(xce, shared_iopage, port, i);
                    if ( ret < 0 )
                        continue;
                }
            }
        }

    }
}

void handle_bufioreq(buf_ioreq_t *buf_ioreq)
{
    if ( !buf_ioreq )
    {
        ERROR("buf_ioreq is null\n");
        return;
    }

    if ( buf_ioreq->type > 8 )
    {
        ERROR("UNKNOWN buf_ioreq type %02x)\n", buf_ioreq->type);
        return;
    }

#if 0
    DEBUG("buf_ioreq: type=%d, pad=%d, dir=%s, size=%d, addr=%x, data=%x\n", 
            buf_ioreq->type, buf_ioreq->pad, buf_ioreq->dir ? "read" : "write",
            buf_ioreq->size,
            buf_ioreq->addr, buf_ioreq->data);
#endif
}

int handle_shared_iopage(xenevtchn_handle *xce, shared_iopage_t *shared_iopage, evtchn_port_t port, 
        size_t vcpu)
{
    struct ioreq *p;

    if ( !shared_iopage )
    {
        ERROR("null sharedio_page\n");
        return -1;
    }

    p = &shared_iopage->vcpu_ioreq[vcpu];
    if ( !p )
    {
        ERROR("null vcpu_ioreq\n");
        return -1;
    }

    handle_pio(xce, port, p);
    return 0;
}

int main(int argc, char **argv)
{
    xc_interface *xc_handle;
    xc_dominfo_t domain_info;
    xendevicemodel_handle *dmod;
    xenforeignmemory_handle *fmem;
    xenevtchn_handle *xce;
    struct xs_handle *xsh;
    xenforeignmemory_resource_handle *fmem_resource;
    evtchn_port_t bufioreq_remote_port;
    evtchn_port_t bufioreq_local_port;
    shared_iopage_t *shared_iopage;
    buffered_iopage_t *buffered_iopage;
    bool secureboot_enabled;
    bool enforcement_level;
    int logfd;
    int domid;
    uint64_t ioreq_server_pages_cnt;
    size_t vcpu_count = 1;
    ioservid_t ioservid;
    char *logfile_name;
    int ret;
    int option_index = 0;
    int i;
    char pidstr[21];
    char pidalive[0x80];
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
            fmem, domid, ioservid, &shared_iopage,
            &buffered_iopage,
            &fmem_resource);
    if ( ret < 0 )
    {
        ERROR("Failed to map ioreq server: %d, %s\n", errno, strerror(errno));
        goto close_evtchn;
    }

    DEBUG("Mapped ioreq server\n");
    INFO("shared_iopage = %p\n", shared_iopage);
    INFO("buffered_iopage = %p\n", buffered_iopage);

    ret = xendevicemodel_get_ioreq_server_info(dmod, domid, ioservid, 0, 0, &bufioreq_remote_port);
    if ( ret < 0 )
    {
        ERROR("Failed to get ioreq server info: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto unmap_resource;
    }

    /* Enable the ioreq server state */
    ret = xendevicemodel_set_ioreq_server_state(dmod, domid, ioservid, 1);
    if ( ret < 0 )
    {
        ERROR("Failed to enable ioreq server: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto unmap_resource;
    }

    /* Initialize Port IO for domU */
    INFO("%lu vCPU(s)\n", vcpu_count);
    evtchn_port_t *remote_vcpu_ports = malloc(sizeof(evtchn_port_t) * vcpu_count);

    for ( i=0; i<vcpu_count; i++ )
    {
        ret = xenevtchn_bind_interdomain(xce, domid, shared_iopage->vcpu_ioreq[i].vp_eport);
        if ( ret < 0 )
        {
            ERROR("failed to bind evtchns: %d, %s\n", errno, strerror(errno));
            goto unmap_resource;
        }

        remote_vcpu_ports[i] = ret;
    }

    for ( i=0; i<vcpu_count; i++ )
    {
        printf("VCPU%d: %u -> %u\n", i, remote_vcpu_ports[i], shared_iopage->vcpu_ioreq[i].vp_eport);
    }

    ret = xenevtchn_bind_interdomain(xce, domid, bufioreq_remote_port);
    if ( ret < 0 )
    {
        ERROR("failed to bind evtchns: %d, %s\n", errno, strerror(errno));
        goto unmap_resource;
    }
    bufioreq_local_port = ret;

    ret = setup_portio(dmod, fmem, domid, ioservid);
    if ( ret < 0 )
    {
        ERROR("failed to init port io: %d\n", ret);
        goto unmap_resource;
    }

    xsh = xs_open(0);
    if ( !xsh )
    {
        ERROR("Couldn\'t open xenstore: %d, %s", errno, strerror(errno));
        goto unmap_resource;
    }

    
    /* Check secure boot is enabled */
    secureboot_enabled = varstored_xs_read_bool(xsh, "/local/domain/%u/platform/secureboot", domid);
    INFO("Secure boot enabled: %s\n", secureboot_enabled ? "true" : "false");

    /* Check enforcment level */
    enforcement_level = varstored_xs_read_bool(xsh, "/local/domain/%u/platform/auth-enforce", domid);
    INFO("Authenticated variables: %s\n", enforcement_level ? "enforcing" : "permissive");

    /* Store the varstored pid in XenStore to signal to XAPI that varstored is alive */
    ret =  snprintf(pidalive, sizeof(pidalive), "/local/domain/%u/varstored-pid", domid);
    if ( ret < 0 )
    {
        ERROR("buffer error: %d, %s\n", errno, strerror(errno));
        goto unmap_resource;
    }

    DEBUG("%s:%d\n", __func__, __LINE__);
    ret = snprintf(pidstr, sizeof(pidstr), "%u", getpid());
    if ( ret < 0 )
    {
        ERROR("pidstr asprintf failed\n");
    }

    ret = xs_write(xsh, XBT_NULL, pidalive, pidstr, ret);
    if ( ret == false )
    {
        ERROR("xs_write failed: %d, %s\n", errno, strerror(errno));
        goto unmap_resource;
    }

    DEBUG("xs_write(%s=%s)\n", pidalive, pidstr);

    /* TODO: Containerize varstored */

    /* Initialize UEFI variables */
    ret = db_init();
    if ( ret < 0 )
    {
        DEBUG("Failed to initialize db\n");
        goto unmap_resource;
    }

    /* Initialize UEFI keys */

    INFO("Starting handler loop!\n");
    /* Initialize event channel handler */
    handler_loop(xce, buffered_iopage, bufioreq_local_port, remote_vcpu_ports, vcpu_count, shared_iopage);

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
    xendevicemodel_destroy_ioreq_server(xendevicemodel_handle,(uint64_t)domain,(uint64_t)ioservid);

    xendevicemodel_set_ioreq_server_state
    (xendevicemodel_handle,(uint64_t)domain,(uint64_t)ioservid,0);
#endif
error:
    free(logfile_name);
    return ret;
}
