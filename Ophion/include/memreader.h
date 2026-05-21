/*
 * memreader.h - Cross-process kernel memory I/O for external clients
 *
 * Provides IOCTLs for usermode tools to read/write the address space of
 * any process by PID. Bypasses anti-cheat ObRegisterCallbacks handle
 * stripping because we attach via KeStackAttachProcess in ring 0.
 */
#pragma once

#include <ntddk.h>

#define IOCTL_HV_MEM_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_MEM_WRITE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_MEM_BASE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MEMREADER_MAX_SIZE  0x10000  /* 64KB per request */

#pragma pack(push, 1)

/* Input for IOCTL_HV_MEM_READ / IOCTL_HV_MEM_WRITE.
 * Output buffer (read) gets the bytes read; (write) is unused. */
typedef struct _MEMREADER_REQUEST {
    UINT32  pid;
    UINT32  size;       /* bytes; capped to MEMREADER_MAX_SIZE */
    UINT64  address;    /* target VA in target process */
    /* For WRITE: source bytes follow this header in the same input buffer */
    UINT8   data[1];
} MEMREADER_REQUEST, *PMEMREADER_REQUEST;

/* Input for IOCTL_HV_MEM_BASE — find module base by name in target process. */
typedef struct _MEMREADER_BASE_REQUEST {
    UINT32  pid;
    UINT32  reserved;
    char    module_name[64];   /* ASCII, null-terminated; e.g. "BigCat-Win64-Shipping.exe" */
} MEMREADER_BASE_REQUEST, *PMEMREADER_BASE_REQUEST;

typedef struct _MEMREADER_BASE_REPLY {
    UINT64  base;
    UINT32  size;
    UINT32  reserved;
} MEMREADER_BASE_REPLY, *PMEMREADER_BASE_REPLY;

#pragma pack(pop)

NTSTATUS memreader_read (UINT32 pid, UINT64 address, PVOID dst, UINT32 size, UINT32 * out_read);
NTSTATUS memreader_write(UINT32 pid, UINT64 address, PVOID src, UINT32 size, UINT32 * out_written);
NTSTATUS memreader_get_module_base(UINT32 pid, const char * module_name,
                                   UINT64 * out_base, UINT32 * out_size);
