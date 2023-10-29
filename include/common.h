#ifndef COMMON_H
#define COMMON_H

#include <mach/mach_time.h>     // mach_absolute_time
#include <mach-o/loader.h>

uint64_t nanoseconds_to_mach_time(uint64_t ns);

#define TIMER_START(timer) \
uint64_t timer = mach_absolute_time();

#define TIMER_SLEEP_UNTIL(timer, ns) \
do \
{ \
mach_wait_until(timer + nanoseconds_to_mach_time(ns)); \
} while(0)

typedef struct
{
    struct
    {
        uintptr_t data;
        uintptr_t pad;
        uintptr_t type;
    } lock; // mutex lock
    uint32_t ref_count;
    int active;
    char pad[0x2f0 /* TASK_BSDINFO */ - sizeof(int) - sizeof(uint32_t) - (3 * sizeof(uintptr_t))];
    uintptr_t bsd_info;
} ktask64_t;

typedef struct __attribute__((__packed__))
{
    uint32_t ip_bits;
    uint32_t ip_references;
    struct __attribute__((__packed__))
    {
        uintptr_t data;
        uint32_t pad;
        uint32_t type;
    } ip_lock; // spinlock
    struct __attribute__((__packed__))
    {
        struct __attribute__((__packed__))
        {
            struct __attribute__((__packed__))
            {
                uint32_t flags;
                uintptr_t waitq_interlock;
                uint32_t pad;
                struct __attribute__((__packed__))
                {
                    uintptr_t next;
                    uintptr_t prev;
                } waitq_queue;
            } waitq;
            uintptr_t messages;
            natural_t msgcount;
            natural_t qlimit;
            natural_t seqno;
            natural_t receiver_name;
            uint32_t  fullwaiters;
            natural_t pset_count;
            uint32_t pad1;
            uint32_t pad2;
        } port;
    } ip_messages;
    uintptr_t ip_receiver;
    uintptr_t ip_kobject;
    uintptr_t ip_nsrequest;
    uintptr_t ip_pdrequest;
    uintptr_t ip_requests;
    uintptr_t ip_premsg;
    natural_t ip_mscount;
    natural_t ip_srights;
    natural_t ip_sorights;
    natural_t ip_sprequests;
    uint64_t  ip_context;
} kport64_t;

typedef struct
{
    struct
    {
        uintptr_t data;
        uintptr_t pad;
        uintptr_t type;
    } lock; // mutex lock
    uint32_t ref_count;
    int active;
    char pad[0x1f0 /* TASK_BSDINFO */ - sizeof(int) - sizeof(uint32_t) - (3 * sizeof(uintptr_t))];
    uintptr_t bsd_info;
} ktask32_t;

typedef struct __attribute__((__packed__))
{
    uint32_t ip_bits;
    uint32_t ip_references;
    struct __attribute__((__packed__))
    {
        uint32_t data;
        uint32_t pad;
        uint32_t type;
    } ip_lock;
    struct __attribute__((__packed__))
    {
        struct __attribute__((__packed__))
        {
            struct __attribute__((__packed__))
            {
                uint32_t flags;
                uintptr_t waitq_interlock;
                struct __attribute__((__packed__))
                {
                    uintptr_t next;
                    uintptr_t prev;
                } waitq_queue;
            } waitq;
            uintptr_t messages;
            natural_t msgcount;
            natural_t qlimit;
            natural_t seqno;
            natural_t receiver_name;
            uint32_t  fullwaiters;
            natural_t pset_count;
        } port;
    } ip_messages;
    uintptr_t ip_receiver;
    uintptr_t ip_kobject;
    uintptr_t ip_nsrequest;
    uintptr_t ip_pdrequest;
    uintptr_t ip_requests;
    uintptr_t ip_premsg;
    natural_t ip_mscount;
    natural_t ip_srights;
    natural_t ip_sorights;
    natural_t ip_sprequests;
    uint64_t  ip_context;
} kport32_t;

#ifdef __LP64__
#   define KBASE_OFFSET        0x2000
#   define ADDR "0x%016llx"
#   define KERNEL_BASE_ADDRESS 0xFFFFFF8002002000
    typedef uint64_t addr_t;
#   define MACH_MAGIC MH_MAGIC_64
    typedef struct mach_header_64 mach_hdr_t;
    typedef struct segment_command_64 mach_seg_t;
    typedef struct section_64 mach_sec_t;
    typedef kport64_t kport_t;
    typedef ktask64_t ktask_t;
#else
#   define ADDR "0x%08x"
#   define KERNEL_BASE_ADDRESS 0x80001000
    typedef uint32_t addr_t;
#   define MACH_MAGIC MH_MAGIC
    typedef struct mach_header mach_hdr_t;
    typedef struct segment_command mach_seg_t;
    typedef struct section mach_sec_t;
    typedef kport32_t kport_t;
    typedef ktask32_t ktask_t;
#endif /* __LP64__ */


#define SIZE "0x%016lx"
typedef struct load_command mach_cmd_t;

#ifndef MIN
#   define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

#endif
