#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>

#include <xenctrl.h>
#include <xenevtchn.h>
#include <xendevicemodel.h>
#include <xenforeignmemory.h>
#include <xen/hvm/params.h>
#include <xen/hvm/dm_op.h>

#define varserviced_fprintf(fd, ...)                    \
    do {                                                \
        fprintf(fd, "varserviced_initialize: ");        \
        fprintf(fd, __VA_ARGS__);                       \
        fflush(fd);                                     \
    } while( 0 )

#define varserviced_error(...) varserviced_fprintf(stderr, "ERROR: " __VA_ARGS__)
#define varserviced_info(...) varserviced_fprintf(stdout,  "INFO: "   __VA_ARGS__)

#ifdef DEBUG
#define varserviced_debug(...) varserviced_fprintf(stdout, "DEBUG: " __VA_ARGS__)
#else
#define varserviced_debug(...) ((void)0)
#endif

#define USAGE                           \
    "Usage: varserviced <options> \n"   \
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
    do {                                                        \
        varserviced_error(opt " option not implemented!\n");    \
        exit(1);                                                \
    } while(0)

int main(int argc, char **argv)

{
    xc_interface *xc_handle;
    xc_dominfo_t domain_info;
    xendevicemodel_handle *dmod;
    xenforeignmemory_handle *fmem;
    xenevtchn_handle *xce;

    int domid;
    uint64_t ioreq_server_pages_cnt;
    int vcpu_count;
    ioservid_t ioreq_server_id;

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
        {"help", no_argument,          0, 'h'},
        {0, 0, 0, 0},
    };

    if ( argc == 1 )
    {
        printf(USAGE);
        exit(1);
    }

    while ( 1 )
    {
        c = getopt_long(argc, argv, "d:rnpu:g:c:i:b:h",
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
            varserviced_info("servicing UEFI variables for Domain %s\n", optarg);
            domid = options[option_index].val;
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
        varserviced_error("Failed to open xc_interface handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto error;
    }

    /* Get info on the domain */
    ret = xc_domain_getinfo(xc_handle, domid, 1, &domain_info);
    if ( ret < 0 )
    {
        ret = errno;
        varserviced_error("Domid %u, xc_domain_getinfo error: %d, %s\n", domid, errno, strerror(errno));
        goto cleanup;
    }

    /* Verify the requested domain == the returned domain */
    if ( domid != domain_info.domid )
    {
        ret = errno;
        varserviced_error("Domid %u does not match expected %u\n", domain_info.domid, domid);
        goto cleanup;
    }

    /* Retrieve IO req server page count, retry until available */
    for ( i=0; i<10; i++ )
    {
        ret = xc_hvm_param_get(xc_handle, domid, HVM_PARAM_NR_IOREQ_SERVER_PAGES, &ioreq_server_pages_cnt);
        if ( ret < 0 )
        {
            varserviced_error("xc_hvm_param_get failed: %d, %s\n", errno, strerror(errno));
            goto cleanup;
        }

        if ( ioreq_server_pages_cnt != 0 )
            break;

        printf("Waiting for ioreq server");
        usleep(100000);
    }
    varserviced_info("HVM_PARAM_NR_IOREQ_SERVER_PAGES = %ld\n", ioreq_server_pages_cnt);

    /* Close hypervisor interface */
    xc_interface_close(xc_handle);
    xc_handle = NULL;

    /* Open xen device model */
    dmod = xendevicemodel_open(0, 0);
    if ( !dmod )
    {
        varserviced_error("Failed to open xendevicemodel handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto cleanup;
    }

    /* Open xen foreign memory interface */
    fmem = xenforeignmemory_open(0, 0);
    if ( !fmem )
    {
        varserviced_error("Failed to open xenforeignmemory handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto close_dmod;
    }

    /* Open xen event channel */
    xce = xenevtchn_open(NULL, 0);
    if ( !xce )
    {
        varserviced_error("Failed to open evtchn handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto close_fmem;
    }

    /* Restrict varserviced's privileged accesses */
    ret = xentoolcore_restrict_all(domid);
    if ( ret < 0 )
    {
        varserviced_error("Failed to restrict Xen handles: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto close_evtchn;
    }

    /* Create an IO Req server for Port IO requests in the port
     * range 0x100 to 0x103.  XenVariable in OVMF uses 0x100,
     * 0x101-0x103 are reserved.
     */
    ret = xendevicemodel_create_ioreq_server(dmod, domid, 1, &ioreq_server_id);
    if ( ret < 0 )
    {
        varserviced_error("Failed to create ioreq server: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto close_evtchn;
    }

    /* Map ioreq server to domU */

    /* Get ioreq server info */

    /* Set the ioreq server state to ready */

    /* Setup memory to receive port IO RPC requests */

    /* Bind the interdomain event channel */

    /* Initialize Port IO for domU */

    /* Check secure boot is enabled */

    /* Check enforcment level */

    /* Store the varserved pid in XenStore */

    /* Containerize varserviced */

    /* Initialize UEFI variables */

    /* Initialize UEFI keys */

    /* Initialize event channel handler */
done:
    return 0;

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
    xenforeignmemory_unmap_resource(xenforeignmemory_handle);
    xendevicemodel_destroy_ioreq_server(xendevicemodel_handle,(ulong)domain,(ulong)ioreq_server_id);

    xendevicemodel_set_ioreq_server_state
    (xendevicemodel_handle,(ulong)domain,(ulong)ioreq_server_id,0);
#endif
error:
    return ret;
}

