#ifndef KERNEL_H
#define KERNEL_H

#include <mach/mach.h>
#include <common.h>

extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

extern mach_port_t tfp0_sp;

kern_return_t copyin_sp(void* to, addr_t from, size_t size);
kern_return_t copyout_sp(addr_t to, void* from, size_t size);

kern_return_t kread32_sp(addr_t addr, uint32_t* retval);
kern_return_t kread64_sp(addr_t addr, uint64_t* retval);
kern_return_t kreadptr_sp(addr_t addr, addr_t* retval);

kern_return_t kwrite8_sp(addr_t addr, uint8_t val);
kern_return_t kwrite16_sp(addr_t addr, uint16_t val);
kern_return_t kwrite32_sp(addr_t addr, uint32_t val);
kern_return_t kwrite64_sp(addr_t addr, uint64_t val);
kern_return_t kwriteptr_sp(addr_t addr, addr_t val);

kern_return_t kalloc_sp(addr_t* retval, vm_size_t size);
kern_return_t kfree_sp(mach_vm_address_t addr, vm_size_t size);

#endif
