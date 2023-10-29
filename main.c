#ifndef APP
#include <mach/mach.h>
#include <unistd.h>
#include <stdbool.h>

#include <plog.h>
#include <common.h>
#include <sockpuppet.h>

addr_t self_port_address = 0;

int main(void)
{
    addr_t kbase = 0;
    exploit(&kbase);
    
    return 0;
}
#endif
