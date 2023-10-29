#ifndef OFFSETS_H
#define OFFSETS_H

#ifdef __LP64__
/* 64bit ios 9.3.x */
#define TASK_BSDINFO                0x308
#define IPC_PORT_IP_RECEIVER        0x58
#define IPC_PORT_IP_KOBJECT         0x60
#define IPC_PORT_IP_SRIGHTS         0x94
#define BSDINFO_PID                 0x10
#define BSDINFO_KAUTH_CRED          0x118
#define PROC_P_FD                   0x120
#define FILEDESC_FD_OFILES          0x0
#define FILEPROC_F_FGLOB            0x8
#define FILEGLOB_FG_DATA            0x38
#define PIPE_BUFFER                 0x10
#define TASK_VM_MAP                 0x28
#define TASK_NEXT                   0x30
#define TASK_PREV                   0x38
#define TASK_ITK_SELF               0xe8
#define TASK_ITK_SPACE              0x2a0
#define IPC_SPACE_IS_TABLE          0x20
#define IPC_ENTRY_SIZE              0x18
#define USER_CLIENT_TRAP            0x48
#define VTAB_GET_EXT_TRAP_FOR_IDX   0x5b8
#else
// 32bit ios 9.3.x
#define TASK_BSDINFO                0x200
#define IPC_PORT_IP_RECEIVER        0x4c
#define IPC_PORT_IP_KOBJECT         0x50
#define IPC_PORT_IP_SRIGHTS         0x70
#define BSDINFO_PID                 0x8
#define BSDINFO_KAUTH_CRED          0xa4
#define PROC_P_FD                   0xa8
#define FILEDESC_FD_OFILES          0x0
#define FILEPROC_F_FGLOB            0x8
#define FILEGLOB_FG_DATA            0x28
#define PIPE_BUFFER                 0x10
#define TASK_VM_MAP                 0x18
#define TASK_NEXT                   0x1c
#define TASK_PREV                   0x20
#define TASK_ITK_SELF               0xa4
#define TASK_ITK_SPACE              0x1b8
#define IPC_SPACE_IS_TABLE          0x18
#define IPC_ENTRY_SIZE              0x10
#define USER_CLIENT_TRAP            0x34
#define VTAB_GET_EXT_TRAP_FOR_IDX   0x384
#endif

#endif
