/*
 *   logger.c - in-memory ring buffer for DbgPrintEx output
 *   safe at PASSIVE/DPC levels only — never call from VMX root mode
 *
 *   atomic append using InterlockedExchangeAdd; truncates when full
 */
#include "hv.h"
#include "logger.h"
#include <ntstrsafe.h>

static char         g_log_buf[HV_LOG_BUF_SIZE];
static volatile LONG g_log_pos = 0;
static BOOLEAN       g_log_initialized = FALSE;

VOID
hv_log_init(VOID)
{
    RtlZeroMemory(g_log_buf, sizeof(g_log_buf));
    g_log_pos = 0;
    g_log_initialized = TRUE;
}

VOID
hv_log(PCSTR fmt, ...)
{
    char    tmp[512];
    va_list args;
    size_t  remaining = 0;
    int     len;
    LONG    old_pos;
    NTSTATUS st;

    va_start(args, fmt);
    st = RtlStringCbVPrintfA(tmp, sizeof(tmp), fmt, args);
    va_end(args);

    if (st != STATUS_SUCCESS && st != STATUS_BUFFER_OVERFLOW)
        return;

    /* compute actual length */
    if (RtlStringCbLengthA(tmp, sizeof(tmp), &remaining) != STATUS_SUCCESS)
        return;

    len = (int)remaining;
    if (len <= 0)
        return;

    /* also send to kernel debugger if attached */
    DbgPrintEx(0, 0, "%s", tmp);

    if (!g_log_initialized)
        return;

    /* atomic reserve space in ring buffer */
    old_pos = InterlockedExchangeAdd(&g_log_pos, (LONG)len);

    /* if exceeds buffer, truncate (drop overflow rather than wrap to keep simple) */
    if (old_pos + len > (LONG)sizeof(g_log_buf)) {
        if (old_pos >= (LONG)sizeof(g_log_buf))
            return;
        len = (int)sizeof(g_log_buf) - old_pos;
        if (len <= 0)
            return;
    }

    RtlCopyMemory(g_log_buf + old_pos, tmp, (SIZE_T)len);
}

SIZE_T
hv_log_snapshot(PVOID out_buf, SIZE_T out_size)
{
    LONG   pos = g_log_pos;
    SIZE_T to_copy;

    if (pos < 0)
        pos = 0;
    if (pos > (LONG)sizeof(g_log_buf))
        pos = (LONG)sizeof(g_log_buf);

    to_copy = (SIZE_T)pos;
    if (to_copy > out_size)
        to_copy = out_size;

    if (out_buf && to_copy > 0)
        RtlCopyMemory(out_buf, g_log_buf, to_copy);

    return to_copy;
}

SIZE_T
hv_log_size(VOID)
{
    LONG pos = g_log_pos;
    if (pos < 0)
        pos = 0;
    if (pos > (LONG)sizeof(g_log_buf))
        pos = (LONG)sizeof(g_log_buf);
    return (SIZE_T)pos;
}
