#ifndef apfs_own_h
#define apfs_own_h

#include <stdint.h>
#include <sys/types.h>

// Verbatim from lara/kexploit/pe/apfs.m. We only touch uid/gid/mode.
struct apfs_fsnode {
    uint8_t             type;
    uint8_t             _type_pad[7];
    uint64_t            ino;

    union {
        uint64_t        jhash_prev;
        struct {
            uint32_t    _jhash_prev_lo;
            uint16_t    xattr_count;
            uint16_t    xattr_flags;
        };
    };

    uint64_t            jhash_next;

    union {
        uint64_t        parent_ino_or_owner_vnode;
        struct {
            uint32_t    parent_ino_lo;
            uint16_t    parent_sub;
            uint16_t    _parent_pad;
        };
    };

    uint32_t            nstream_id;

    union {
        uint32_t        internal_flags;
        struct {
            uint8_t     reclaim_flag;
            uint8_t     busy_flag;
            uint16_t    internal_flags_hi;
        };
    };

    void                *jhash_gate;

    union {
        uint64_t        internal_link;
        struct {
            uint8_t     _link_base;
            uint8_t     snap_rename_flag;
            uint16_t    _link_pad;
            uint32_t    snap_mount_state;
        };
    };

    uint64_t            graft_state;
    uint64_t            snap_state;
    uint64_t            fake_getattr_data;
    uint64_t            mnomap_data;
    uint64_t            cleanup_data;

    union {
        uint64_t        crypto_state;
        struct {
            uint8_t     _crypto_base;
            uint8_t     crypto_class;
            uint8_t     crypto_flags;
            uint8_t     _crypto_pad;
            uint32_t    crypto_extra;
        };
    };

    uint32_t            bsd_flags;
    uint32_t            gen_flags;
    uint64_t            mmap_state;
    uid_t               uid;
    gid_t               gid;
    uint16_t            mode;
    uint16_t            open_refcnt;
    uint32_t            ino_flags_ext;
    uint64_t            raw_enc_data;
};

// Change a file's owner (uid/gid) by directly writing apfs_fsnode in
// kernel memory. Works regardless of current process uid — bypasses the
// need for true uid=0. Returns 0 on success, -1 on failure.
// Ported from lara/kexploit/pe/apfs.m.
int apfs_own(const char *path, uid_t uid, gid_t gid);

// Change a file's mode. Same mechanism as apfs_own. Returns 0/-1.
int apfs_mod(const char *path, mode_t mode);

// Read current on-disk values via kernel memory (sanity-check helpers).
uint32_t apfs_getuid_kr(const char *path);
uint32_t apfs_getgid_kr(const char *path);
uint16_t apfs_getmode_kr(const char *path);

// Recursively chown every file/dir under `root` to (uid, gid). Uses lstat so
// symlinks are chown'd themselves, not followed. Skips per-entry sync/stat
// for speed; one sync at the end. Returns number of entries successfully
// chown'd. Also sets mode=0777 on every entry.
long apfs_own_tree(const char *root, uid_t uid, gid_t gid);

// Kernel-level variant of apfs_own_tree: walks vnode name cache instead of
// using userspace opendir/lstat. Bypasses DAC permission checks entirely.
// Processes every entry in the vnode tree regardless of Unix permissions.
// Also sets mode=0777 on every entry. Returns number of entries processed.
long apfs_own_tree_kernel(const char *root, uid_t uid, gid_t gid);

// Single-entry kernel-level chown+chmod: takes a vnode directly (obtained
// via get_vnode_for_path_kernel or similar) and writes uid/gid/mode=0777
// to its apfs_fsnode.  Bypasses all DAC checks.  Returns 0 on success, -1
// on failure.
int apfs_own_vnode(uint64_t vnode, uid_t uid, gid_t gid);

#endif /* apfs_own_h */
