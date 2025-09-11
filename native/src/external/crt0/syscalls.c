#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <assert.h>

#define SYS_INLINE
#include "linux_syscall_support.h"

// Some missing declarations
_syscall3(int, faccessat, int, f, const char *, p, int, m)
_syscall2(int, umount2, const char *, t, int, f)
#ifdef __NR_renameat
_syscall4(int, renameat, int, o, const char *, op, int, n, const char *, np)
#else
_syscall5(int, renameat2, int, o, const char *, op, int, n, const char *, np, int, flag)
#endif
_syscall1(mode_t, umask, mode_t, mask)
_syscall1(int, chroot, const char *, path)
_syscall2(int, nanosleep, const struct kernel_timespec *, req, struct kernel_timespec *, rem)
_syscall5(int, mount, const char *, s, const char *, t,
          const char *, fs, unsigned long, f, const void *, d)
_syscall3(int, symlinkat, const char *, t, int, fd, const char *, l)
_syscall3(int, mkdirat, int, dirfd, const char *, pathname, mode_t, mode)
_syscall4(ssize_t, sendfile, int, out_fd, int, in_fd, off_t *, offset, size_t, count)
_syscall5(int, linkat, int, o, const char *, op, int, n, const char *, np, int, f)
_syscall4(int, mknodat, int, dirfd, const char *, pathname, mode_t, mode, dev_t, dev)
_syscall2(int, fchmod, int, fd, mode_t, mode)
_syscall4(int, fchmodat, int, dirfd, const char *, pathname, mode_t, mode, int, flags)
_syscall5(int, fchownat, int, dirfd, const char *, p, uid_t, owner, gid_t, group, int, flags)
_syscall3(ssize_t, readv, int, fd, const struct kernel_iovec*, v, size_t, c)
_syscall5(int, pselect6, fd_set*, s1, fd_set*, s2, fd_set*, s3, struct kernel_timespec*, ts, void*, p)
_syscall4(ssize_t, fgetxattr, int, fd, const char *, n, void *, v, size_t, s)
_syscall4(ssize_t, fsetxattr, int, fd, const char *, n, void *, v, size_t, s)

#define SYMBOL_ALIAS(from, to) \
__asm__(".global " #from " \n " #from " = " #to)

#define EXPORT_SYMBOL(name) \
SYMBOL_ALIAS(name, sys_##name)

EXPORT_SYMBOL(openat);
EXPORT_SYMBOL(close);
EXPORT_SYMBOL(read);
EXPORT_SYMBOL(symlink);
EXPORT_SYMBOL(write);
EXPORT_SYMBOL(writev);
EXPORT_SYMBOL(unlink);
EXPORT_SYMBOL(munmap);
EXPORT_SYMBOL(mremap);
EXPORT_SYMBOL(readlink);
EXPORT_SYMBOL(unlinkat);
EXPORT_SYMBOL(getpid);
EXPORT_SYMBOL(chdir);
EXPORT_SYMBOL(umount2);
EXPORT_SYMBOL(readlinkat);
EXPORT_SYMBOL(umask);
EXPORT_SYMBOL(chroot);
EXPORT_SYMBOL(mount);
EXPORT_SYMBOL(symlinkat);
EXPORT_SYMBOL(mkdirat);
EXPORT_SYMBOL(ioctl);
EXPORT_SYMBOL(fork);
EXPORT_SYMBOL(sendfile);
EXPORT_SYMBOL(ftruncate);
EXPORT_SYMBOL(linkat);
EXPORT_SYMBOL(mknodat);
EXPORT_SYMBOL(fchmod);
EXPORT_SYMBOL(fchmodat);
EXPORT_SYMBOL(fchownat);
EXPORT_SYMBOL(readv);
EXPORT_SYMBOL(lseek);
EXPORT_SYMBOL(execve);
EXPORT_SYMBOL(getdents64);
EXPORT_SYMBOL(clock_gettime);
EXPORT_SYMBOL(nanosleep);
EXPORT_SYMBOL(sigemptyset);
EXPORT_SYMBOL(sigaddset);
EXPORT_SYMBOL(sigprocmask);
EXPORT_SYMBOL(raise);
EXPORT_SYMBOL(getxattr);
EXPORT_SYMBOL(setxattr);
EXPORT_SYMBOL(lgetxattr);
EXPORT_SYMBOL(lsetxattr);
EXPORT_SYMBOL(fgetxattr);
EXPORT_SYMBOL(fsetxattr);

SYMBOL_ALIAS(_exit, sys_exit_group);
SYMBOL_ALIAS(openat64, openat);
SYMBOL_ALIAS(statfs64, statfs);
SYMBOL_ALIAS(stat64, stat);
SYMBOL_ALIAS(lstat64, lstat);

#if defined(__LP64__)

_syscall3(int, fchown, int, i, uid_t, u, gid_t, g)
EXPORT_SYMBOL(fchown);
EXPORT_SYMBOL(fstat);
EXPORT_SYMBOL(mmap);
EXPORT_SYMBOL(statfs);
SYMBOL_ALIAS(fstatat, sys_newfstatat);
SYMBOL_ALIAS(lseek64, lseek);
SYMBOL_ALIAS(ftruncate64, ftruncate);
SYMBOL_ALIAS(mmap64, mmap);

#else

_syscall3(int, fchown32, int, i, uid_t, u, gid_t, g)
_syscall2(int, ftruncate64, int, i, off64_t, off)
_syscall3(int, fcntl64, int, fd, int, op, long, arg)
EXPORT_SYMBOL(ftruncate64);
EXPORT_SYMBOL(fstat64);
EXPORT_SYMBOL(fstatat64);
SYMBOL_ALIAS(fstat, fstat64);
SYMBOL_ALIAS(fstatat, fstatat64);
SYMBOL_ALIAS(fchown, sys_fchown32);

// Source: bionic/libc/bionic/legacy_32_bit_support.cpp
off64_t lseek64(int fd, off64_t off, int whence) {
    off64_t result;
    unsigned long off_hi = (unsigned long) (off >> 32);
    unsigned long off_lo = (unsigned long) off;
    if (sys__llseek(fd, off_hi, off_lo, &result, whence) < 0) {
        return -1;
    }
    return result;
}

// Source: bionic/libc/bionic/legacy_32_bit_support.cpp
#define MMAP2_SHIFT 12 // 2**12 == 4096

void *mmap64(void* addr, size_t size, int prot, int flags, int fd, off64_t offset) {
    if (offset < 0 || (offset & ((1UL << MMAP2_SHIFT)-1)) != 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    // Prevent allocations large enough for `end - start` to overflow.
    size_t rounded = __BIONIC_ALIGN(size, getpagesize());
    if (rounded < size || rounded > PTRDIFF_MAX) {
        errno = ENOMEM;
        return MAP_FAILED;
    }

    return sys__mmap2(addr, size, prot, flags, fd, offset >> MMAP2_SHIFT);
}

void *mmap(void *addr, size_t size, int prot, int flags, int fd, off_t offset) {
    return mmap64(addr, size, prot, flags, fd, (off64_t) offset);
}

static_assert(sizeof(struct statfs) == sizeof(struct kernel_statfs64), "");

int statfs(const char* path, struct statfs* result) {
    return sys__statfs64(path, sizeof(*result), (void *) result);
}

#endif

int lstat(const char* path, struct stat *st) {
    return fstatat(AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW);
}

int stat(const char* path, struct stat *st) {
    return fstatat(AT_FDCWD, path, st, 0);
}

int lchown(const char* path, uid_t uid, gid_t gid) {
    return fchownat(AT_FDCWD, path, uid, gid, AT_SYMLINK_NOFOLLOW);
}

int chown(const char* path, uid_t uid, gid_t gid) {
    return fchownat(AT_FDCWD, path, uid, gid, 0);
}

int chmod(const char* path, mode_t mode) {
    return sys_fchmodat(AT_FDCWD, path, mode, 0);
}

int mkfifoat(int fd, const char* path, mode_t mode) {
    return sys_mknodat(fd, path, (mode & ~S_IFMT) | S_IFIFO, 0);
}

int mkfifo(const char* path, mode_t mode) {
    return mkfifoat(AT_FDCWD, path, mode);
}

int mknod(const char* path, mode_t mode, dev_t dev) {
    return sys_mknodat(AT_FDCWD, path, mode, dev);
}

int link(const char *oldpath, const char *newpath) {
    return sys_linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

int rmdir(const char *path) {
    return sys_unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

int mkdir(const char *pathname, mode_t mode) {
    return sys_mkdirat(AT_FDCWD, pathname, mode);
}

int symlink(const char *target, const char *linkpath) {
    return sys_symlinkat(target, AT_FDCWD, linkpath);
}

int rename(const char *oldpath, const char *newpath) {
#ifdef __NR_renameat
    return sys_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
#else
    return sys_renameat2(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
#endif
}

#ifdef __NR_renameat
EXPORT_SYMBOL(renameat);
#else
int renameat(int o, const char * op, int n, const char * np) {
    return sys_renameat2(o, op, n, np, 0);
}
#endif

int access(const char* path, int mode) {
    return faccessat(AT_FDCWD, path, mode, 0);
}

int remove(const char *path) {
    int r = sys_unlinkat(AT_FDCWD, path, 0);
    if (r < 0 && errno == EISDIR) {
        r = sys_unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
    }
    return r;
}

int creat(const char *path, mode_t mode) {
    return sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

sighandler_t signal(int sig, sighandler_t handler) {
    struct kernel_sigaction sa = { .sa_handler_ = handler, .sa_flags = SA_RESTART };
    return (sys_sigaction(sig, &sa, &sa) == -1) ? SIG_ERR : sa.sa_handler_;
}

int open(const char *pathname, int flags, ...) {
    int mode = 0;

    if (((flags & O_CREAT) == O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

#if !defined(__LP64__)
    flags |= O_LARGEFILE;
#endif

    return sys_openat(AT_FDCWD, pathname, flags, mode);
}
