/*
 * Copyright (C) 2010       Citrix Ltd.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

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
#include <xenforeignmemory.h>
#include <xen/hvm/dm_op.h>
#include <xen/hvm/ioreq.h>
#include <xen/hvm/params.h>
#include <xen/io/ring.h>
#include <xen/memory.h>

#include "common.h"

#define MAX_CPUS 1

#define hw_error ERROR
#define error_report ERROR

//#define DEBUG_XEN_HVM
#define PRIx64 "lu"

#ifdef DEBUG_XEN_HVM
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "xen: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define TARGET_PAGE_SIZE (4<<10)

static xc_interface *xen_xc;
extern xendevicemodel_handle *xen_dmod;
extern xenforeignmemory_handle *xen_fmem;
//static ioservid_t ioservid;
extern const unsigned long portio_port_start;
extern const unsigned long portio_port_end;
extern domid_t xen_domid;

void destroy_hvm_domain(bool reboot);

/* Compatibility with older version */

/* This allows QEMU to build on a system that has Xen 4.5 or earlier
 * installed.  This here (not in hw/xen/xen_common.h) because xen/hvm/ioreq.h
 * needs to be included before this block and hw/xen/xen_common.h needs to
 * be included before xen/hvm/ioreq.h
 */
#ifndef IOREQ_TYPE_VMWARE_PORT
#define IOREQ_TYPE_VMWARE_PORT  3
struct vmware_regs {
    uint32_t esi;
    uint32_t edi;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};
typedef struct vmware_regs vmware_regs_t;

struct shared_vmport_iopage {
    struct vmware_regs vcpu_vmport_regs[1];
};
typedef struct shared_vmport_iopage shared_vmport_iopage_t;
#endif

static inline uint32_t xen_vcpu_eport(shared_iopage_t *shared_page, int i)
{
    return shared_page->vcpu_ioreq[i].vp_eport;
}
static inline ioreq_t *xen_vcpu_ioreq(shared_iopage_t *shared_page, int vcpu)
{
    return &shared_page->vcpu_ioreq[vcpu];
}

#define BUFFER_IO_MAX_DELAY  100

typedef uint64_t hwaddr;

typedef struct XenIOState {
    ioservid_t ioservid;
    shared_iopage_t *shared_page;
    shared_vmport_iopage_t *shared_vmport_page;
    buffered_iopage_t *buffered_iopage;
    int *cpu_by_vcpu_id;
    /* the evtchn port for polling the notification, */
    evtchn_port_t *ioreq_local_port;
    /* evtchn remote and local ports for buffered io */
    evtchn_port_t bufioreq_remote_port;
    evtchn_port_t bufioreq_local_port;
    /* the evtchn fd for polling */
    xenevtchn_handle *xce_handle;
    /* which vcpu we are serving */
    int send_vcpu;

    struct xs_handle *xenstore;
    hwaddr free_phys_offset;
    /* Buffer used by xen_sync_dirty_bitmap */
    unsigned long *dirty_bitmap;
} XenIOState;

static void show_shared_iopage(shared_iopage_t *shared_iopage)
{
    int i;

    if ( !shared_iopage )
    {
        DEBUG("shared_iopage=NULL\n");
        return;
    }

    for ( i=0; i<MAX_CPUS; i++ )
    {
        struct ioreq *p = &shared_iopage->vcpu_ioreq[i];

        DEBUG(
                "ioreq: addr=0x%lx,"
                " data=0x%lx,"
                " count=0x%x,"
                " size=0x%x,"
                " vp_eport=0x%x,"
                " state=0x%x,"
                " data_is_ptr=0x%x,"
                " dir=0x%x,"
                " type=0x%x\n",
                p->addr,
                p->data,
                p->count,
                p->size,
                p->vp_eport,
                p->state,
                p->data_is_ptr,
                p->dir,
                p->type
        );
    }
}

static void show_buffered_iopage(buffered_iopage_t *buffered_iopage)
{
    buf_ioreq_t *p;
    int i;

    if ( !buffered_iopage )
    {
        DEBUG("buffered_iopage=NULL\n");
        return;
    }


    DEBUG("sizeof(buf_ioreq_t) == %lu\n", sizeof(buf_ioreq_t));

    for (i=0; i<IOREQ_BUFFER_SLOT_NUM; i++)
    {
        p = &buffered_iopage->buf_ioreq[i];
        DEBUG(
            "&buf_ioreq[%d]=%p, "
            " type=0x%x,"
            " pad=0x%x,"
            " dir=0x%x,"
            " size=0x%x,"
            " addr=0x%x,"
            " data=0x%x\n",
            i,
            p,
            p->type,
            p->pad,
            p->dir,
            p->size,
            p->addr,
            p->data
        );
    }
}



void show_state(XenIOState *state)
{
    DEBUG("*****************************************************\n");
    DEBUG("XenIOState: ioservid=%u, shared_page=%p, buffered_iopage=%p, "
            "bufioreq_remote_port=%u, bufioreq_local_port=%u\n",
            state->ioservid, state->shared_page, state->buffered_iopage,
            state->bufioreq_remote_port,
            state->bufioreq_local_port);

    show_shared_iopage(state->shared_page);
    show_buffered_iopage(state->buffered_iopage);
    DEBUG("*****************************************************\n");
}

/* get the ioreq packets from share mem */
static ioreq_t *cpu_get_ioreq_from_shared_memory(XenIOState *state, int vcpu)
{
    TRACE();
    ioreq_t *req = xen_vcpu_ioreq(state->shared_page, vcpu);

    if (req->state != STATE_IOREQ_READY) {
        DEBUG("I/O request not ready: "
                "%x, ptr: %x, port: %"PRIx64", "
                "data: %"PRIx64", count: %u, size: %u\n",
                req->state, req->data_is_ptr, req->addr,
                req->data, req->count, req->size);
        return NULL;
    }

    xen_rmb(); /* see IOREQ_READY /then/ read contents of ioreq */

    req->state = STATE_IOREQ_INPROCESS;
    return req;
}

typedef unsigned long target_ulong;

#if 0
/*
 * Helper functions which read/write an object from/to physical guest
 * memory, as part of the implementation of an ioreq.
 *
 * Equivalent to
 *   cpu_physical_memory_rw(addr + (req->df ? -1 : +1) * req->size * i,
 *                          val, req->size, 0/1)
 * except without the integer overflow problems.
 */
static void rw_phys_req_item(hwaddr addr,
                             ioreq_t *req, uint32_t i, void *val, int rw)
{
    /* Do everything unsigned so overflow just results in a truncated result
     * and accesses to undesired parts of guest memory, which is up
     * to the guest */
    hwaddr offset = (hwaddr)req->size * i;
    if (req->df) {
        addr -= offset;
    } else {
        addr += offset;
    }
    cpu_physical_memory_rw(addr, val, req->size, rw);
}


static inline void read_phys_req_item(hwaddr addr,
                                      ioreq_t *req, uint32_t i, void *val)
{
    rw_phys_req_item(addr, req, i, val, 0);
}
static inline void write_phys_req_item(hwaddr addr,
                                       ioreq_t *req, uint32_t i, void *val)
{
    rw_phys_req_item(addr, req, i, val, 1);
}

static void do_outp(uint32_t addr,
        unsigned long size, uint32_t val)
{
    switch (size) {
#if 0
        case 1:
            return cpu_outb(addr, val);
        case 2:
            return cpu_outw(addr, val);
        case 4:
            return cpu_outl(addr, val);
#else
        case 1:
            cpu_outb(addr, val);
            break;
        case 2:
            cpu_outw(addr, val);
            break;
        case 4:
            cpu_outl(addr, val);
            break;
        default:
            hw_error("outp: bad size: %04x %lx\n", addr, size);
            break;
#endif
    }
}

static uint32_t do_inp(uint32_t addr, unsigned long size)
{
    switch (size) {
        case 1:
            return cpu_inb(addr);
        case 2:
            return cpu_inw(addr);
        case 4:
            return cpu_inl(addr);
        default:
            hw_error("inp: bad size: %04x %lx\n", addr, size);
    }
}
#else
static uint32_t do_inp(uint32_t addr, unsigned long size)
{
    (void) addr;
    (void) size;
    return 0;
}
static void do_outp(uint32_t addr,
        unsigned long size, uint32_t val)
{
    (void) addr;
    (void) size;
    (void) val;
}
static inline void read_phys_req_item(hwaddr addr,
                                      ioreq_t *req, uint32_t i, void *val)
{
    (void) addr;
    (void) req;
    (void) val;
}
static inline void write_phys_req_item(hwaddr addr,
                                       ioreq_t *req, uint32_t i, void *val)
{
    (void) addr;
    (void) req;
    (void) val;
}
#endif

static void cpu_ioreq_pio(ioreq_t *req)
{
    uint32_t i;

    if (req->size > sizeof(uint32_t)) {
        hw_error("PIO: bad size (%u)\n", req->size);
    }

    if (req->dir == IOREQ_READ) {
        if (!req->data_is_ptr) {
            req->data = do_inp(req->addr, req->size);
        } else {
            uint32_t tmp;

            for (i = 0; i < req->count; i++) {
                tmp = do_inp(req->addr, req->size);
                write_phys_req_item(req->data, req, i, &tmp);
            }
        }
    } else if (req->dir == IOREQ_WRITE) {
        if (!req->data_is_ptr) {
            do_outp(req->addr, req->size, req->data);
        } else {
            for (i = 0; i < req->count; i++) {
                uint32_t tmp = 0;

                read_phys_req_item(req->data, req, i, &tmp);
                do_outp(req->addr, req->size, tmp);
            }
        }
    }
}

static void cpu_ioreq_move(ioreq_t *req)
{
    uint32_t i;

    if (req->size > sizeof(req->data)) {
        hw_error("MMIO: bad size (%u)\n", req->size);
    }

    if (!req->data_is_ptr) {
        if (req->dir == IOREQ_READ) {
            for (i = 0; i < req->count; i++) {
                read_phys_req_item(req->addr, req, i, &req->data);
            }
        } else if (req->dir == IOREQ_WRITE) {
            for (i = 0; i < req->count; i++) {
                write_phys_req_item(req->addr, req, i, &req->data);
            }
        }
    } else {
        uint64_t tmp;

        if (req->dir == IOREQ_READ) {
            for (i = 0; i < req->count; i++) {
                read_phys_req_item(req->addr, req, i, &tmp);
                write_phys_req_item(req->data, req, i, &tmp);
            }
        } else if (req->dir == IOREQ_WRITE) {
            for (i = 0; i < req->count; i++) {
                read_phys_req_item(req->data, req, i, &tmp);
                write_phys_req_item(req->addr, req, i, &tmp);
            }
        }
    }
}

static void handle_ioreq(XenIOState *state, ioreq_t *req)
{
    if (!req->data_is_ptr && (req->dir == IOREQ_WRITE) &&
            (req->size < sizeof (target_ulong))) {
        req->data &= ((target_ulong) 1 << (8 * req->size)) - 1;
    }

    switch (req->type) {
        case IOREQ_TYPE_PIO:
            cpu_ioreq_pio(req);
            break;
        case IOREQ_TYPE_COPY:
            cpu_ioreq_move(req);
            break;
        default:
            hw_error("Invalid ioreq type 0x%x\n", req->type);
    }
}

static int handle_buffered_iopage(XenIOState *state)
{
    buffered_iopage_t *buf_page = state->buffered_iopage;
    buf_ioreq_t *buf_req = NULL;
    ioreq_t req;
    int qw;

    if (!buf_page) {
        return 0;
    }

    memset(&req, 0x00, sizeof(req));
    req.state = STATE_IOREQ_READY;
    req.count = 1;
    req.dir = IOREQ_WRITE;

    for (;;) {
        uint32_t rdptr = buf_page->read_pointer, wrptr;

        xen_rmb();
        wrptr = buf_page->write_pointer;
        xen_rmb();
        if (rdptr != buf_page->read_pointer) {
            continue;
        }
        if (rdptr == wrptr) {
            break;
        }
        buf_req = &buf_page->buf_ioreq[rdptr % IOREQ_BUFFER_SLOT_NUM];
        req.size = 1U << buf_req->size;
        req.addr = buf_req->addr;
        req.data = buf_req->data;
        req.type = buf_req->type;
        xen_rmb();
        qw = (req.size == 8);
        if (qw) {
            if (rdptr + 1 == wrptr) {
                hw_error("Incomplete quad word buffered ioreq\n");
            }
            buf_req = &buf_page->buf_ioreq[(rdptr + 1) %
                                           IOREQ_BUFFER_SLOT_NUM];
            req.data |= ((uint64_t)buf_req->data) << 32;
            xen_rmb();
        }

        handle_ioreq(state, &req);

        /* Only req.data may get updated by handle_ioreq(), albeit even that
         * should not happen as such data would never make it to the guest (we
         * can only usefully see writes here after all).
         */
        assert(req.state == STATE_IOREQ_READY);
        assert(req.count == 1);
        assert(req.dir == IOREQ_WRITE);
        assert(!req.data_is_ptr);

        atomic_add(&buf_page->read_pointer, qw + 1);
    }

    return req.count;
}

static void handle_buffered_io(void *opaque)
{
    XenIOState *state = opaque;

    if (!handle_buffered_iopage(state))
    {
        xenevtchn_unmask(state->xce_handle, state->bufioreq_local_port);
    }
}

/* use poll to get the port notification */
/* ioreq_vec--out,the */
/* retval--the number of ioreq packet */
static ioreq_t *cpu_get_ioreq(XenIOState *state)
{
    unsigned int max_cpus = MAX_CPUS;
    int i;
    int ret;
    evtchn_port_t port;

    port = xenevtchn_pending(state->xce_handle);

    /* unmask the wanted port again */
    ret = xenevtchn_unmask(state->xce_handle, port);
    DEBUG("xenevtchn_unmask() == %d\n", ret);

    if (port == state->bufioreq_local_port) {
        DEBUG("%s:%d: buffered, port=%u\n", __func__, __LINE__, port);
        handle_buffered_io(state);
        return NULL;
    }

    if (port != -1) {
        for (i = 0; i < max_cpus; i++) {
            if (state->ioreq_local_port[i] == port) {
                break;
            }
        }

        if (i == max_cpus) {
            ERROR("Fatal error while trying to get io event!\n");
        }


        /* get the io packet from shared memory */
        state->send_vcpu = i;
        DEBUG("%s:%d: calling cpu_get_ioreq_from_shared_memory\n", __func__, __LINE__);
        return cpu_get_ioreq_from_shared_memory(state, i);
    }

    /* read error or read nothing */
    return NULL;
}

static void cpu_handle_ioreq(XenIOState *state)
{
    ioreq_t *req = cpu_get_ioreq(state);

    handle_buffered_iopage(state);
    DEBUG("%s:%d: req=%p\n", __func__, __LINE__, req);
    if (req) {
        ioreq_t copy = *req;

        xen_rmb();
        handle_ioreq(state, &copy);
        req->data = copy.data;

        if (req->state != STATE_IOREQ_INPROCESS) {
            fprintf(stderr, "Badness in I/O request ... not in service?!: "
                    "%x, ptr: %x, port: %"PRIx64", "
                    "data: %"PRIx64", count: %u, size: %u, type: %u\n",
                    req->state, req->data_is_ptr, req->addr,
                    req->data, req->count, req->size, req->type);
            destroy_hvm_domain(false);
            return;
        }

        xen_wmb(); /* Update ioreq contents /then/ update state. */
        TRACE();

        req->state = STATE_IORESP_READY;
        xenevtchn_notify(state->xce_handle,
                         state->ioreq_local_port[state->send_vcpu]);
        TRACE();
    }
}

void wait_for_event(int evtchn_fd, XenIOState *state)
{
    int ret;
    struct pollfd pollfd;
    evtchn_port_t port;

    pollfd.fd = evtchn_fd; 
    pollfd.events = POLLIN | POLLERR;

    while ( true )
    {
        TRACE();
        ret = poll(&pollfd, 1, -1);

        if ( ret < 0 )
        {
            ERROR("poll error on fd %d: %d, %s\n", pollfd.fd, errno, strerror(errno));
            usleep(100000);
            continue;
        }



        port = xenevtchn_pending(state->xce_handle);

        if (port == state->bufioreq_local_port)
        {
            DEBUG("%s:%d: buffered, port=%u\n", __func__, __LINE__, port);
            handle_buffered_io(state);
        } 
        else if  ( port == state->ioreq_local_port )
        {
        }

        show_state(state);
        cpu_handle_ioreq(state);
    }
}


static void xen_main_loop(XenIOState *state)
{
    int evtchn_fd = -1;

    if (state->xce_handle != NULL) {
        evtchn_fd = xenevtchn_fd(state->xce_handle);
    }

    if (evtchn_fd != -1) {
        wait_for_event(evtchn_fd, state);
    }
}

#define RUN_STATE_RUNNING 1

#if 0
static void xen_exit_notifier(XenIOState *state, void *data)
{
    xen_destroy_ioreq_server(xen_domid, state->ioservid);
    xenevtchn_close(state->xce_handle);
    xs_daemon_close(state->xenstore);
}
#endif

#if 0
static inline int xen_get_vmport_regs_pfn(xc_interface *xc, domid_t dom,
                                          xen_pfn_t *vmport_regs_pfn)
{
    int rc;
    uint64_t value;
    rc = xc_hvm_param_get(xc, dom, HVM_PARAM_VMPORT_REGS_PFN, &value);
    if (rc >= 0) {
        *vmport_regs_pfn = (xen_pfn_t) value;
    }
    return rc;
}
#endif

static int xen_map_ioreq_server(XenIOState *state)
{
    void *addr = NULL;
    xenforeignmemory_resource_handle *fres;
    xen_pfn_t ioreq_pfn;
    xen_pfn_t bufioreq_pfn;
    evtchn_port_t bufioreq_evtchn;
    int rc;

    /*
     * Attempt to map using the resource API and fall back to normal
     * foreign mapping if this is not supported.
     */
    fres = xenforeignmemory_map_resource(xen_fmem, xen_domid,
                                         XENMEM_resource_ioreq_server,
                                         state->ioservid, 0, 2,
                                         &addr,
                                         PROT_READ | PROT_WRITE, 0);
    if (fres != NULL) {
        state->buffered_iopage = addr;
        state->shared_page = addr + TARGET_PAGE_SIZE;
    } else if (errno != EOPNOTSUPP) {
        DEBUG("failed to map ioreq server resources: error %d handle=%p",
                     errno, xen_xc);
        return -1;
    }

    DEBUG("buffered_iopage=%p\n", state->buffered_iopage);
    DEBUG("shared_iopage=%p\n", state->shared_page);
    DEBUG("XENFORIEGNMEMORY_MAP(1): state->shared_page == NULL, %s\n",
            state->shared_page == NULL ? "true" : "false");

    rc = xendevicemodel_get_ioreq_server_info(xen_dmod, xen_domid, state->ioservid,
                                   (state->shared_page == NULL) ?
                                   &ioreq_pfn : NULL,
                                   (state->buffered_iopage == NULL) ?
                                   &bufioreq_pfn : NULL,
                                   &bufioreq_evtchn);
    if ( rc < 0 ) {
        DEBUG("failed to get ioreq server info: error %d handle=%p",
                     errno, xen_xc);
        return rc;
    }

    DEBUG("XENFORIEGNMEMORY_MAP(2): state->shared_page == NULL, %s\n",
            state->shared_page == NULL ? "true" : "false");
    if ( state->shared_page == NULL )
    {
        DEBUG("XENFORIEGNMEMORY_MAP(3): state->shared_page == NULL, %s\n",
                state->shared_page == NULL ? "true" : "false");
        DEBUG("shared page at pfn %lx\n", ioreq_pfn);

        state->shared_page = xenforeignmemory_map(xen_fmem, xen_domid,
                                                  PROT_READ | PROT_WRITE,
                                                  1, &ioreq_pfn, NULL);
        DEBUG("XENFORIEGNMEMORY_MAP:post\n");
        if (state->shared_page == NULL) {
            error_report("map shared IO page returned error %d handle=%p",
                         errno, xen_xc);
        }
    }

    if (state->buffered_iopage == NULL) {
        DEBUG("buffered io page at pfn %lx\n", bufioreq_pfn);

        state->buffered_iopage = xenforeignmemory_map(xen_fmem, xen_domid,
                                                       PROT_READ | PROT_WRITE,
                                                       1, &bufioreq_pfn,
                                                       NULL);
        if (state->buffered_iopage == NULL) {
            error_report("map buffered IO page returned error %d", errno);
            return -1;
        }
    }

    if (state->shared_page == NULL || state->buffered_iopage == NULL) {
        return -1;
    }

    DEBUG("buffered io evtchn is %x\n", bufioreq_evtchn);

    state->bufioreq_remote_port = bufioreq_evtchn;

    return 0;
}

void xen_hvm_init(void)
{
    unsigned int max_cpus = MAX_CPUS;
    int i, rc;
    XenIOState *state;

#if 0
    xen_pfn_t ioreq_pfn;
#endif

    state = malloc(sizeof (XenIOState));

    state->xce_handle = xenevtchn_open(NULL, 0);
    if (state->xce_handle == NULL) {
        ERROR("xen: event channel open");
        goto err;
    }

    state->xenstore = xs_daemon_open();
    if (state->xenstore == NULL) {
        ERROR("xen: xenstore open");
        goto err;
    }

    rc = xendevicemodel_create_ioreq_server(xen_dmod, xen_domid, HVM_IOREQSRV_BUFIOREQ_LEGACY, &state->ioservid);
    if ( rc < 0 )
    {
        ERROR("xendevicemodel_create_ioreq_server() failed: %d\n", rc);
        goto err;
    }

    rc = xen_map_ioreq_server(state);
    if ( rc < 0 )
    {
        ERROR("xen_map_ioreq_server() failed: %d\n", rc);
        goto err;
    }

#if 0
    rc = xen_get_vmport_regs_pfn(xen_xc, xen_domid, &ioreq_pfn);
    if (!rc) {
        DEBUG("shared vmport page at pfn %lx\n", ioreq_pfn);
        state->shared_vmport_page =
            xenforeignmemory_map(xen_fmem, xen_domid, PROT_READ|PROT_WRITE,
                                 1, &ioreq_pfn, NULL);
        if (state->shared_vmport_page == NULL) {
            error_report("map shared vmport IO page returned error %d handle=%p",
                         errno, xen_xc);
            goto err;
        }
    } else if (rc != -ENOSYS) {
        error_report("get vmport regs pfn returned error %d, rc=%d",
                     errno, rc);
        goto err;
    }
#endif

    /* Note: cpus is empty at this point in init */
    state->cpu_by_vcpu_id = malloc(max_cpus * sizeof(int));

    rc = xendevicemodel_set_ioreq_server_state(xen_dmod, xen_domid, state->ioservid, true);
    if (rc < 0) {
        error_report("failed to enable ioreq server info: error %d handle=%p",
                     errno, xen_xc);
        goto err;
    }

    state->ioreq_local_port = malloc(max_cpus * sizeof (evtchn_port_t));
    show_state(state);

    /* FIXME: how about if we overflow the page here? */
    for (i = 0; i < max_cpus; i++) {
        uint32_t vcpu_eport = xen_vcpu_eport(state->shared_page, i);
        rc = xenevtchn_bind_interdomain(state->xce_handle, xen_domid, vcpu_eport);
        if ( rc == -1 )
        {
            DEBUG("shared evtchn %d bind error %d, xen_domid=%d, vcpu_eport=%u\n",
                    i, errno, xen_domid, vcpu_eport);
            goto err;
        }
        state->ioreq_local_port[i] = rc;
    }

    rc = xenevtchn_bind_interdomain(state->xce_handle, xen_domid,
                                    state->bufioreq_remote_port);
    if (rc == -1) {
        DEBUG("buffered evtchn bind error %d", errno);
        goto err;
    }
    state->bufioreq_local_port = rc;

    rc = xendevicemodel_map_io_range_to_ioreq_server(xen_dmod, xen_domid, state->ioservid,
                                                      0, 0x100, 0x103);
    if ( rc < 0 )
    {
        DEBUG("Failed to map io range to ioreq server: %d, %s\n", errno, strerror(errno));
        goto err;
    }

#if 0
    xen_bus_init();

    /* Initialize backend core & drivers */
    if (xen_be_init() != 0) {
        error_report("xen backend core setup failed");
        goto err;
    }
    xen_be_register_common();
#endif
    xen_main_loop(state);
    return;

err:
    error_report("xen hardware virtual machine initialisation failed");
    exit(1);
}

void destroy_hvm_domain(bool reboot)
{
    xc_interface *xc_handle;
    int sts;
    int rc;

    unsigned int reason = reboot;

    if (xen_dmod) {
        rc = xendevicemodel_shutdown(xen_dmod, xen_domid, reason);
        if (!rc) {
            return;
        }
        if (errno != ENOTTY /* old Xen */) {
            ERROR("xendevicemodel_shutdown failed");
        }
        /* well, try the old thing then */
    }

    xc_handle = xc_interface_open(0, 0, 0);
    if (xc_handle == NULL) {
        fprintf(stderr, "Cannot acquire xenctrl handle\n");
    } else {
        sts = xc_domain_shutdown(xc_handle, xen_domid, reason);
        if (sts != 0) {
            fprintf(stderr, "xc_domain_shutdown failed to issue %s, "
                    "sts %d, %s\n", reboot ? "reboot" : "poweroff",
                    sts, strerror(errno));
        } else {
            fprintf(stderr, "Issued domain %d %s\n", xen_domid,
                    reboot ? "reboot" : "poweroff");

        }
        xc_interface_close(xc_handle);
    }
}

void xen_shutdown_fatal_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "Will destroy the domain.\n");
    /* destroy the domain */
}
