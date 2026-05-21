/*
 * EfiCompat.h - NT-style typedefs bridging Ophion's NT-flavored C code to UEFI
 *
 * Phase 2 port maps Ophion's existing ntddk-style symbols to EFI equivalents.
 * Lets us port vmx.c / ept.c / vmexit.c with minimal source diff.
 */
#pragma once

#include <Uefi.h>
#include <stdint.h>

typedef UINT8    UCHAR;
typedef UINT16   USHORT;
typedef UINT32   ULONG;
typedef UINT64   ULONG64;
typedef UINT64   ULONGLONG;
typedef INT32    LONG;
typedef INT64    LONG64;
typedef UINTN    SIZE_T;
typedef VOID    *PVOID;
typedef UINT8   *PUCHAR;
typedef UINT16  *PUSHORT;
typedef UINT32  *PULONG;
typedef UINT64  *PUINT64;

#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL ((VOID *)0)
#endif

typedef UINT8 BOOLEAN;

// NT-style status
typedef INT32 NTSTATUS;
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL          ((NTSTATUS)0xC0000001L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_INVALID_PARAMETER     ((NTSTATUS)0xC000000DL)

#define NT_SUCCESS(x)  ((x) >= 0)

#ifndef PAGE_SIZE
#define PAGE_SIZE              0x1000
#endif

#ifndef MAXULONG64
#define MAXULONG64              ((UINT64)~((UINT64)0))
#endif

#ifndef DECLSPEC_ALIGN
#define DECLSPEC_ALIGN(x)      __declspec(align(x))
#endif

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x)  ((VOID)(x))
#endif

// LIST_ENTRY + helpers come from EDK2 BaseLib (Base.h ships LIST_ENTRY,
// InitializeListHead, IsListEmpty, InsertHeadList, InsertTailList). No need
// to redefine — the layout is binary-compatible with NTDDK's LIST_ENTRY.

// Kernel pool replacement — backs onto EfiAllocateRuntimePages page count.
PVOID EfiAllocateRuntimePages(SIZE_T Pages);
VOID  EfiFreeRuntimePages(PVOID Buffer, SIZE_T Pages);
