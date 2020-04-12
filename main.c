#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>

#include <xenctrl.h>
#include <xen/hvm/params.h>

#define varserviced_fprintf(fd, ...)                    \
    do {                                                \
        fprintf(fd, "varserviced_initialize:");         \
        fprintf(fd, __VA_ARGS__);                       \
        fflush(stderr);                                 \
    } while(0)

#define varserviced_error(...) varserviced_fprintf(stderr, __VA_ARGS__)
#define varserviced_printf(...) varserviced_fprintf(stdout, __VA_ARGS__)


int main(int argc, char **argv)

{
    xc_interface *xc_handle;
    xc_dominfo_t domain_info;

    int domid;
    uint64_t ioreq_server_pages_cnt;
    int vcpu_count;

    int ret;
    int i;

    /* Gain access to the hypervisor */
    xc_handle = xc_interface_open(0,0,0);
    if (!xc_handle) {
        varserviced_error("Failed to open xc_interface handle: %d, %s\n", errno, strerror(errno));
        ret = errno;
        goto done;
    }

    domid = 1;

    /* Get info on the domain */
    ret = xc_domain_getinfo(xc_handle, domid, 1, &domain_info);
    if (ret < 0) {
        ret = errno;
        varserviced_error("Domid %u, xc_domain_getinfo error: %d, %s\n", domain_info.domid, errno, strerror(errno));
        goto cleanup;
    }

    /* Verify the requested domain == the returned domain */
    if (domid != domain_info.domid) {
        ret = errno;
        varserviced_error("Domid %u does not match expected %u\n", domain_info.domid, domid);
        goto cleanup;
    }

    /* Retrieve IO req server page count, retry until available */
    for (i=0; i<10; i++) {
        ret = xc_hvm_param_get(xc_handle, domid, HVM_PARAM_NR_IOREQ_SERVER_PAGES, &ioreq_server_pages_cnt);
        if (ret < 0) {
            varserviced_error("xc_hvm_param_get failed: %d, %s", errno, strerror(errno));
            goto cleanup;
        }

        if (ioreq_server_pages_cnt != 0)
            break;

        printf("Waiting for ioreq server");
        usleep(100000);
    }
    varserviced_printf("HVM_PARAM_NR_IOREQ_SERVER_PAGES = %ld\n", ioreq_server_pages_cnt);

cleanup:
    xc_interface_close(xc_handle);
done:
    return ret;
}

