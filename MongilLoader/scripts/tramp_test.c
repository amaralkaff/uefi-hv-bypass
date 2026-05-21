/*
 * tramp_test.c - self-test for NtosPatch trampoline byte emitter
 *
 * Replicates NtosBuildTrampoline / NtosBuildInlinePatch from
 * MongilLoader/OphionDxe/NtosPatch.c in a user-mode test harness so we can
 * verify the byte stream is correct without booting MongilLoader.
 *
 * Tests:
 *   1. Inline patch is exactly 14 bytes
 *   2. Inline patch decodes as: mov rax, imm64; jmp rax; nop; nop
 *   3. Trampoline body checks magic in r10 and matches our cmp encoding
 *   4. Saved-prologue replay region is at the expected offset
 *   5. Resume jmp targets nt_va + 14
 *
 * On failure, prints disassembly hint + exits non-zero. CI gate.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define OPHION_VMCALL_MAGIC_HANDLE_U64  0xCAFEDEADBEEF1234ULL
#define NTOS_PATCH_OVERWRITE_BYTES      14
#define TRAMPOLINE_SIZE                 64

// Reproduced from NtosPatch.c. Must stay in lockstep with the EFI driver.
static size_t
build_trampoline(uint8_t *out, uint64_t nt_va, const uint8_t *saved)
{
    size_t n = 0;
    out[n++] = 0x49; out[n++] = 0xBA;
    uint64_t magic = OPHION_VMCALL_MAGIC_HANDLE_U64;
    memcpy(&out[n], &magic, 8); n += 8;

    out[n++] = 0x4C; out[n++] = 0x39; out[n++] = 0xD1;     // cmp rcx, r10
    out[n++] = 0x75; out[n++] = 0x12;                       // jne short +0x12

    out[n++] = 0x48; out[n++] = 0x89; out[n++] = 0xD0;     // mov rax, rdx
    out[n++] = 0x4C; out[n++] = 0x89; out[n++] = 0xC2;     // mov rdx, r8
    out[n++] = 0x4D; out[n++] = 0x89; out[n++] = 0xC8;     // mov r8, r9
    out[n++] = 0x4C; out[n++] = 0x8B; out[n++] = 0x4C;     // mov r9, [rsp+0x28]
    out[n++] = 0x24; out[n++] = 0x28;
    out[n++] = 0x0F; out[n++] = 0x01; out[n++] = 0xC1;     // vmcall
    out[n++] = 0xC3;                                         // ret

    memcpy(&out[n], saved, NTOS_PATCH_OVERWRITE_BYTES); n += NTOS_PATCH_OVERWRITE_BYTES;

    out[n++] = 0x48; out[n++] = 0xB8;
    uint64_t resume = nt_va + NTOS_PATCH_OVERWRITE_BYTES;
    memcpy(&out[n], &resume, 8); n += 8;
    out[n++] = 0xFF; out[n++] = 0xE0;
    return n;
}

static void
build_inline_patch(uint8_t out[NTOS_PATCH_OVERWRITE_BYTES], uint64_t tramp_va)
{
    out[0]  = 0x48; out[1]  = 0xB8;
    memcpy(&out[2], &tramp_va, 8);
    out[10] = 0xFF; out[11] = 0xE0;
    out[12] = 0x90; out[13] = 0x90;
}

static int g_fail = 0;

#define EXPECT(cond, msg) do {                              \
    if (!(cond)) {                                          \
        fprintf(stderr, "FAIL: %s  (line %d)\n", msg, __LINE__); \
        g_fail++;                                            \
    }                                                        \
} while (0)

static void
hex_dump(const char *label, const uint8_t *p, size_t n)
{
    printf("%s [%zu bytes]:", label, n);
    for (size_t i = 0; i < n; ++i) {
        if (i % 16 == 0) printf("\n  ");
        printf("%02x ", p[i]);
    }
    printf("\n");
}

static int
test_inline_patch(void)
{
    printf("--- test_inline_patch ---\n");
    uint8_t patch[NTOS_PATCH_OVERWRITE_BYTES];
    uint64_t fake_tramp = 0xFFFFAABBCCDD0010ULL;
    build_inline_patch(patch, fake_tramp);

    hex_dump("inline_patch", patch, sizeof(patch));

    // Expected: 48 B8 <8 bytes LE> FF E0 90 90
    EXPECT(patch[0] == 0x48, "byte 0 (REX.W)");
    EXPECT(patch[1] == 0xB8, "byte 1 (mov rax, imm64 opcode)");
    uint64_t imm;
    memcpy(&imm, &patch[2], 8);
    EXPECT(imm == fake_tramp, "imm64 matches trampoline VA");
    EXPECT(patch[10] == 0xFF, "byte 10 (jmp rax opcode)");
    EXPECT(patch[11] == 0xE0, "byte 11 (jmp rax modrm)");
    EXPECT(patch[12] == 0x90 && patch[13] == 0x90, "trailing NOPs");
    return 0;
}

static int
test_trampoline(void)
{
    printf("--- test_trampoline ---\n");
    uint8_t  saved[NTOS_PATCH_OVERWRITE_BYTES];
    for (int i = 0; i < NTOS_PATCH_OVERWRITE_BYTES; ++i) saved[i] = (uint8_t)(0xA0 + i);

    uint8_t  buf[TRAMPOLINE_SIZE] = {0};
    uint64_t fake_nt_va = 0xFFFFF80100123456ULL;

    size_t n = build_trampoline(buf, fake_nt_va, saved);
    hex_dump("trampoline", buf, n);

    EXPECT(n == 59, "trampoline length = 59 bytes");

    // Magic check region
    EXPECT(buf[0] == 0x49 && buf[1] == 0xBA, "mov r10, imm64 prefix");
    uint64_t magic_in_buf;
    memcpy(&magic_in_buf, &buf[2], 8);
    EXPECT(magic_in_buf == OPHION_VMCALL_MAGIC_HANDLE_U64, "magic bytes match");

    EXPECT(buf[10] == 0x4C && buf[11] == 0x39 && buf[12] == 0xD1, "cmp rcx, r10");
    EXPECT(buf[13] == 0x75 && buf[14] == 0x12, "jne +0x12");

    // Magic-match path
    EXPECT(buf[15] == 0x48 && buf[16] == 0x89 && buf[17] == 0xD0, "mov rax, rdx");
    EXPECT(buf[18] == 0x4C && buf[19] == 0x89 && buf[20] == 0xC2, "mov rdx, r8");
    EXPECT(buf[21] == 0x4D && buf[22] == 0x89 && buf[23] == 0xC8, "mov r8, r9");
    EXPECT(buf[24] == 0x4C && buf[25] == 0x8B && buf[26] == 0x4C, "mov r9, [rsp+0x28] prefix");
    EXPECT(buf[27] == 0x24 && buf[28] == 0x28, "[rsp+0x28] modrm/sib/disp8");
    EXPECT(buf[29] == 0x0F && buf[30] == 0x01 && buf[31] == 0xC1, "vmcall");
    EXPECT(buf[32] == 0xC3, "ret");

    // jne offset 0x12 = 18 bytes from end of jne (byte 15) = byte 33. We
    // emitted 18 bytes (bytes 15..32) for the magic-match path, so fall_through
    // begins at byte 33.
    size_t fall_through_off = 15 + 0x12;  // = 33
    EXPECT(fall_through_off == 33, "jne lands at fall_through offset");
    for (int i = 0; i < NTOS_PATCH_OVERWRITE_BYTES; ++i) {
        EXPECT(buf[fall_through_off + i] == saved[i], "saved-prologue byte matches");
    }

    // Resume jmp at fall_through + 14
    size_t resume_off = fall_through_off + NTOS_PATCH_OVERWRITE_BYTES;
    EXPECT(buf[resume_off] == 0x48 && buf[resume_off + 1] == 0xB8, "mov rax, resume_va prefix");
    uint64_t resume_va;
    memcpy(&resume_va, &buf[resume_off + 2], 8);
    EXPECT(resume_va == fake_nt_va + NTOS_PATCH_OVERWRITE_BYTES, "resume = nt_va + 14");
    EXPECT(buf[resume_off + 10] == 0xFF && buf[resume_off + 11] == 0xE0, "jmp rax (resume)");

    return 0;
}

int
main(void)
{
    test_inline_patch();
    test_trampoline();
    if (g_fail) {
        printf("\n=== FAIL: %d assertions failed ===\n", g_fail);
        return 1;
    }
    printf("\n=== PASS ===\n");
    return 0;
}
