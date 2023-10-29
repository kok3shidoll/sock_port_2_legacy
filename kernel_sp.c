#include <mach/mach.h>

#include <plog.h>
#include <sockpuppet.h>
#include <common.h>
#include <io.h>
#include <kernel.h>

mach_port_t tfp0_sp = 0;

kern_return_t copyin_sp(void* to, addr_t from, size_t size)
{
    kern_return_t r = KERN_SUCCESS;
    
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x800)
    {
        size = 0x800;
    }
    size_t off = 0;
    while (1)
    {
        r = mach_vm_read_overwrite(tfp0_sp, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0)
        {
            break;
        }
        size = szt;
        if (size > 0x800)
        {
            size = 0x800;
        }
    }
    return r;
}

kern_return_t copyout_sp(addr_t to, void* from, size_t size)
{
    return mach_vm_write(tfp0_sp, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

kern_return_t kread32_sp(addr_t addr, uint32_t* retval)
{
    kern_return_t r = KERN_SUCCESS;
    uint32_t val = 0;
    r = copyin_sp(&val, addr, 4);
    if(r == KERN_SUCCESS)
    {
        *retval = val;
    }
    return r;
}

kern_return_t kread64_sp(addr_t addr, uint64_t* retval)
{
    kern_return_t r = KERN_SUCCESS;
    uint64_t val = 0;
    r = copyin_sp(&val, addr, 8);
    if(r == KERN_SUCCESS)
    {
        *retval = val;
    }
    return r;
}

kern_return_t kreadptr_sp(addr_t addr, addr_t* retval)
{
#ifdef __LP64__
    return kread64_sp(addr, retval);
#else
    return kread32_sp(addr, retval);
#endif
}

kern_return_t kwrite8_sp(addr_t addr, uint8_t val)
{
    return copyout_sp(addr, &val, 1);
}

kern_return_t kwrite16_sp(addr_t addr, uint16_t val)
{
    return copyout_sp(addr, &val, 2);
}

kern_return_t kwrite32_sp(addr_t addr, uint32_t val)
{
    return copyout_sp(addr, &val, 4);
}

kern_return_t kwrite64_sp(addr_t addr, uint64_t val)
{
    return copyout_sp(addr, &val, 8);
}

kern_return_t kwriteptr_sp(addr_t addr, addr_t val)
{
#ifdef __LP64__
    return kwrite64_sp(addr, val);
#else
    return kwrite32_sp(addr, val);
#endif
}

kern_return_t kalloc_sp(addr_t* retval, vm_size_t size)
{
    kern_return_t r = KERN_SUCCESS;
    mach_vm_address_t addr = 0;
    r = mach_vm_allocate(tfp0_sp, (mach_vm_address_t *)&addr, size, VM_FLAGS_ANYWHERE);
    if(r == KERN_SUCCESS)
    {
        *retval = addr;
    }
    return r;
}

kern_return_t kfree_sp(mach_vm_address_t addr, vm_size_t size)
{
    return mach_vm_deallocate(tfp0_sp, addr, size);
}
