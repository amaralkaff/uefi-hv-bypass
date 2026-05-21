// ophn_hash_check.c - Phase 5f: verify VMM-computed cheat exe hash matches
// independent SHA-256 over our own .text section.
//
// VMM hashes target's .text via PT-walk in caller_cr3 during REGISTER.
// We compute SHA-256 over our own .text via direct read, then read VMM's
// computed hash via OPHR subleaves 17-20, compare.
//
// Compile: cl /O2 /nologo ophn_hash_check.c bcrypt.lib /Fe:ophn_hash_check.exe

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#pragma comment(lib, "bcrypt.lib")

#define OP_REGISTER       0x01
#define OP_UNREGISTER     0x05
#define MAGIC_HANDLE      ((HANDLE)0xCAFEDEADBEEF1234ULL)
#define OPHR              0x4F504852

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PfnNtCreateCrossVmEvent)(HANDLE, PVOID, ULONG, PVOID, ULONG);

#pragma pack(push, 1)
typedef struct { uint8_t image_sha256[32]; uint64_t image_base; uint32_t image_size; uint32_t reserved; } reg_req_t;
typedef struct { uint64_t session_key; uint32_t version; uint32_t status; } reg_resp_t;
typedef struct { reg_req_t req; reg_resp_t resp; } reg_combo_t;
#pragma pack(pop)

static int compute_self_text_hash(uint8_t out[32], uint64_t *text_va_out, uint32_t *text_size_out) {
    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((uint8_t *)self + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    uint64_t text_va = 0;
    uint32_t text_size = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            text_va   = (uint64_t)(uintptr_t)self + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }
    if (!text_va) return 1;
    *text_va_out = text_va;
    *text_size_out = text_size;

    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE h;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0);
    BCryptHashData(h, (PUCHAR)(uintptr_t)text_va, text_size, 0);
    BCryptFinishHash(h, out, 32, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}

int main(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PfnNtCreateCrossVmEvent fn = (PfnNtCreateCrossVmEvent)GetProcAddress(ntdll, "NtCreateCrossVmEvent");

    uint8_t local_hash[32];
    uint64_t my_text_va = 0;
    uint32_t my_text_size = 0;
    if (compute_self_text_hash(local_hash, &my_text_va, &my_text_size)) {
        printf(".text scan failed\n"); return 1;
    }
    printf("self .text  va=0x%llx size=0x%x\n", (unsigned long long)my_text_va, my_text_size);
    printf("local hash  ");
    for (int i = 0; i < 32; i++) printf("%02x", local_hash[i]);
    printf("\n");

    HMODULE self = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)self;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((uint8_t *)self + dos->e_lfanew);

    reg_combo_t reg = {0};
    reg.req.image_base = (uint64_t)(uintptr_t)self;
    reg.req.image_size = nt->OptionalHeader.SizeOfImage;
    NTSTATUS s = fn(MAGIC_HANDLE, NULL, OP_REGISTER, &reg, sizeof(reg));
    printf("REGISTER NTSTATUS=0x%lx resp.status=0x%x key=0x%llx\n",
           s, reg.resp.status, (unsigned long long)reg.resp.session_key);

    int s17[4], s18[4], s19[4], s20[4];
    __cpuidex(s17, OPHR, 17);
    __cpuidex(s18, OPHR, 18);
    __cpuidex(s19, OPHR, 19);
    __cpuidex(s20, OPHR, 20);

    uint64_t vmm_text_va = ((uint64_t)(unsigned)s17[2] << 32) | (uint64_t)(unsigned)s17[1];
    uint32_t vmm_text_sz = (unsigned)s17[3];
    uint8_t vmm_hash[32];
    *(uint32_t *)&vmm_hash[0]  = (uint32_t)s18[1];
    *(uint32_t *)&vmm_hash[4]  = (uint32_t)s18[2];
    *(uint32_t *)&vmm_hash[8]  = (uint32_t)s18[3];
    *(uint32_t *)&vmm_hash[12] = (uint32_t)s19[1];
    *(uint32_t *)&vmm_hash[16] = (uint32_t)s19[2];
    *(uint32_t *)&vmm_hash[20] = (uint32_t)s19[3];
    *(uint32_t *)&vmm_hash[24] = (uint32_t)s20[1];
    *(uint32_t *)&vmm_hash[28] = (uint32_t)s20[2];

    printf("VMM .text   va=0x%llx size=0x%x\n", (unsigned long long)vmm_text_va, vmm_text_sz);
    printf("VMM hash    ");
    for (int i = 0; i < 32; i++) printf("%02x", vmm_hash[i]);
    printf("\n");

    int match = (memcmp(local_hash, vmm_hash, 32) == 0);
    printf("MATCH       %s\n", match ? "PASS" : "FAIL");
    if (vmm_text_va == my_text_va && vmm_text_sz == my_text_size) {
        printf("text region MATCH\n");
    } else {
        printf("text region MISMATCH (VMM walked different bytes)\n");
    }

    fn(MAGIC_HANDLE, (PVOID)reg.resp.session_key, OP_UNREGISTER, NULL, 0);
    return match ? 0 : 1;
}
