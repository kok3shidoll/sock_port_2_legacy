#ifndef OFFSETS_H
#define OFFSETS_H

#ifdef __LP64__
/* 64bit ios 8.x */
#define TASK_BSDINFO                0x2f0 /* ok */
#define IPC_PORT_IP_RECEIVER        0x60  /* ok */
#define IPC_PORT_IP_KOBJECT         0x68  /* ok */
#define IPC_PORT_IP_SRIGHTS         0x94
#define BSDINFO_PID                 0x10  /* ok */
#define BSDINFO_KAUTH_CRED          0xe8
#define PROC_P_FD                   0xf0  /* ok */
#define FILEDESC_FD_OFILES          0x0   /* ok */
#define FILEPROC_F_FGLOB            0x8   /* ok */
#define FILEGLOB_FG_DATA            0x38  /* ok */
#define PIPE_BUFFER                 0x10  /* ok */
#define TASK_VM_MAP                 0x28  /* ok */
#define TASK_NEXT                   0x30  /* ok */
#define TASK_PREV                   0x38  /* ok */
#define TASK_ITK_SELF               0xe8  /* ok */
#define TASK_ITK_SPACE              0x288 /* ok */
#define IPC_SPACE_IS_TABLE          0x20  /* ok */
#define IPC_ENTRY_SIZE              0x18
#define USER_CLIENT_TRAP            0x48
#define VTAB_GET_EXT_TRAP_FOR_IDX   0x5b8
#else
// 32bit ios 8.x
#define TASK_BSDINFO                0x1f0 /* ok */
#define IPC_PORT_IP_RECEIVER        0x40
#define IPC_PORT_IP_KOBJECT         0x44  /* ok */
#define IPC_PORT_IP_SRIGHTS         0x5c
#define BSDINFO_PID                 0x8
#define BSDINFO_KAUTH_CRED          0x8c
#define PROC_P_FD                   0x90  /* ok */
#define FILEDESC_FD_OFILES          0x0   /* ok */
#define FILEPROC_F_FGLOB            0x8   /* ok */
#define FILEGLOB_FG_DATA            0x28  /* ok */
#define PIPE_BUFFER                 0x10  /* ok */
#define TASK_VM_MAP                 0x18
#define TASK_NEXT                   0x1c
#define TASK_PREV                   0x20
#define TASK_ITK_SELF               0xa4  /* ok */
#define TASK_ITK_SPACE              0x1a8 /* ok */
#define IPC_SPACE_IS_TABLE          0x18
#define IPC_ENTRY_SIZE              0x10
#define USER_CLIENT_TRAP            0x50
#define VTAB_GET_EXT_TRAP_FOR_IDX   0x384
#endif

#endif
