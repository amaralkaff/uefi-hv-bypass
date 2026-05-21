/*
 *   logger.h - in-memory ring buffer logger for DbgPrintEx output
 *   safe at PASSIVE/DPC levels only — do NOT call from VMX root mode
 */
#pragma once

#include <ntddk.h>
#include <stdarg.h>

#define HV_LOG_BUF_SIZE  (128 * 1024)

VOID    hv_log_init(VOID);
VOID    hv_log(PCSTR fmt, ...);
SIZE_T  hv_log_snapshot(PVOID out_buf, SIZE_T out_size);
SIZE_T  hv_log_size(VOID);
