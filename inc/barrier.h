#ifndef __H_BARRIER
#define __H_BARRIER

/* Taken/modified from Linux 4.20 */

#include <stdint.h>

#define barrier() asm volatile("": : :"memory")

#define smp_mb() __sync_synchronize()

static inline
void __read_once_size(const volatile void *p, void *res, int size)
{
    switch (size) {
    case 1: *(uint8_t *)res = *(volatile uint8_t *)p; break;
    case 2: *(uint16_t *)res = *(volatile uint16_t *)p; break;
    case 4: *(uint32_t *)res = *(volatile uint32_t *)p; break;
    case 8: *(uint64_t *)res = *(volatile uint64_t *)p; break;
    default:
        barrier();
        __builtin_memcpy((void *)res, (const void *)p, size);
        barrier();
    }
}


#if defined(__x86_64__) || defined(__arm__)
# define smp_read_barrier_depends() do {} while(0)
#else
# error "smp_read_barrier_depends() not yet implemented for this architecture"
#endif

#define __READ_ONCE(x)                                                   \
    ({                                                                          \
        union { typeof(x) __val; char __c[1]; } __u;                            \
        __read_once_size(&(x), __u.__c, sizeof(x));                             \
        smp_read_barrier_depends(); /* Enforce dependency ordering from x */    \
        __u.__val;                                                              \
    })

#define READ_ONCE(x) __READ_ONCE(x)

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
    switch (size) {
    case 1: *(volatile uint8_t *)p = *(uint8_t *)res; break;
    case 2: *(volatile uint16_t *)p = *(uint16_t *)res; break;
    case 4: *(volatile uint32_t *)p = *(uint32_t *)res; break;
    case 8: *(volatile uint64_t *)p = *(uint64_t *)res; break;
    default:
        barrier();
        __builtin_memcpy((void *)p, (const void *)res, size);
        barrier();
    }
}

#define WRITE_ONCE(x, val) \
    ({                          \
        union { typeof(x) __val; char __c[1]; } __u =   \
                { .__val = (typeof(x)) (val) }; \
        __write_once_size(&(x), __u.__c, sizeof(x));    \
        __u.__val;                                      \
    })


#endif
