/*
 * VmmUtil.c - VA/PA + segment descriptor helpers for UEFI port.
 *
 * Phase 2 contract:
 *   - va_to_pa: identity (UEFI guarantees identity until SetVirtualAddressMap;
 *     post-EBS we need private host CR3, but our VMM allocations live in
 *     EfiRuntimeServicesCode pages — those are the same physical RAM either way).
 *   - pa_to_va: identity (same reason).
 *   - get_system_cr3: just __readcr3() at boot time. Real Ophion reads the
 *     kernel system process CR3 (PsInitialSystemProcess + 0x28); not available
 *     in EFI. Phase 2.5 will populate this with our private host CR3 instead.
 *
 * segment_get_descriptor / segment_fill_vmcs ported verbatim from
 * Ophion/src/util.c (pure GDT walking, no Windows deps).
 */
#include <intrin.h>
#include "EfiCompat.h"
#include "ia32.h"

UINT64
va_to_pa(PVOID va)
{
    return (UINT64)(UINTN)va;  // identity in UEFI pre-Phase-2.5
}

PVOID
pa_to_va(UINT64 pa)
{
    return (PVOID)(UINTN)pa;
}

UINT64
get_system_cr3(VOID)
{
    return __readcr3();
}

VOID
segment_get_descriptor(PUCHAR gdt_base, UINT16 selector, VMX_SEGMENT_SELECTOR *result)
{
    PSEGMENT_DESCRIPTOR_32 desc;
    UINT16                 index;

    if (!result)
        return;

    // GDT index = upper 13 bits of the selector.
    index = (UINT16)((selector >> 3) & 0x1FFF);

    if (selector == 0 || index == 0) {
        result->Selector = 0;
        result->Base = 0;
        result->Limit = 0;
        result->Attributes.AsUInt = 0;
        result->Attributes.Unusable = TRUE;
        return;
    }

    desc = (PSEGMENT_DESCRIPTOR_32)(gdt_base + index * 8);

    result->Selector = selector;

    result->Base = (UINT64)desc->BaseLow |
                   ((UINT64)desc->BaseMid << 16) |
                   ((UINT64)desc->BaseHigh << 24);

    // System segments (TSS, LDT) in long mode are 16-byte descriptors;
    // the next entry holds the upper 32 bits of the base.
    if (!desc->System) {
        UINT64 base_high = *(UINT64 *)(gdt_base + index * 8 + 8);
        result->Base |= (base_high & 0xFFFFFFFFULL) << 32;
    }

    result->Limit = (UINT32)desc->LimitLow |
                    ((UINT32)desc->LimitHigh << 16);

    if (desc->Granularity) {
        result->Limit = (result->Limit << 12) | 0xFFF;
    }

    result->Attributes.AsUInt    = 0;
    result->Attributes.Type        = desc->Type;
    result->Attributes.System      = desc->System;
    result->Attributes.Dpl         = desc->Dpl;
    result->Attributes.Present     = desc->Present;
    result->Attributes.Avl         = desc->Avl;
    result->Attributes.LongMode    = desc->LongMode;
    result->Attributes.DefaultBig  = desc->DefaultBig;
    result->Attributes.Granularity = desc->Granularity;
    result->Attributes.Unusable    = 0;
}

VOID
segment_fill_vmcs(PVOID gdt_base, UINT32 seg_reg, UINT16 selector)
{
    VMX_SEGMENT_SELECTOR seg = {0};

    segment_get_descriptor((PUCHAR)gdt_base, selector, &seg);

    if (selector == 0) {
        seg.Attributes.Unusable = TRUE;
    }

    seg.Attributes.Reserved1 = 0;
    seg.Attributes.Reserved2 = 0;

    // Each VMCS guest-segment family is offset by seg_reg * 2.
    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR      + seg_reg * 2, selector);
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT         + seg_reg * 2, seg.Limit);
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS + seg_reg * 2, seg.Attributes.AsUInt);
    __vmx_vmwrite(VMCS_GUEST_ES_BASE          + seg_reg * 2, seg.Base);
}
