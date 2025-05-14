#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "stdio_impl.h"

// Hand-rolled base FILE operations

static int fp_read_fn(void *p, char *buf, int sz) {
    intptr_t fd = (intptr_t) p;
    return read(fd, buf, sz);
}

static int fp_write_fn(void *p, const char *buf, int sz) {
    intptr_t fd = (intptr_t) p;
    return write(fd, buf, sz);
}

static int fp_close_fn(void *p) {
    intptr_t fd = (intptr_t) p;
    return close(fd);
}

static int buf_read_fn(void *p, char *buf, int sz) {
    buf_holder *h = (buf_holder *) p;
    size_t len;
    if (h->end) {
        len = MIN(h->begin + sz, h->end) - h->begin;
    } else {
        len = sz;
    }
    if (len) {
        memcpy(buf, h->begin, len);
        h->begin += len;
    }
    return sz;
}

static int buf_write_fn(void *p, const char *buf, int sz) {
    buf_holder *h = (buf_holder *) p;
    size_t len;
    if (h->end) {
        len = MIN(h->begin + sz, h->end) - h->begin;
    } else {
        len = sz;
    }
    if (len) {
        memcpy(h->begin, buf, len);
        h->begin += len;
    }
    return sz;
}

void setup_fd_fp(file_impl *fp, int fd) {
    fp->fd = fd;
    fp->cookie = NULL;
    fp->read_fn = fp_read_fn;
    fp->write_fn = fp_write_fn;
    fp->close_fn = fp_close_fn;
}

void setup_buf_fp(file_impl *fp, buf_holder *h) {
    fp->fd = -1;
    fp->buf = h;
    fp->read_fn = buf_read_fn;
    fp->write_fn = buf_write_fn;
    fp->close_fn = NULL;
}

static file_impl __stdio_fp[3];

FILE* stdin  = (FILE *) &__stdio_fp[0];
FILE* stdout = (FILE *) &__stdio_fp[1];
FILE* stderr = (FILE *) &__stdio_fp[2];

void __init_stdio(void) {
    setup_fd_fp(&__stdio_fp[0], 0);
    setup_fd_fp(&__stdio_fp[1], 1);
    setup_fd_fp(&__stdio_fp[2], 2);
}

FILE *fopen(const char *path, const char *mode) {
    int flag = 0;
    int mode_flg = 0;
    if (*mode == 'r') {
        flag |= O_RDONLY;
    } else if (*mode == 'w') {
        flag |= O_WRONLY | O_CREAT | O_TRUNC;
    } else if (*mode == 'a') {
        flag |= O_WRONLY | O_CREAT | O_APPEND;
    }
    if (strchr(mode, 'e')) flag |= O_CLOEXEC;
    if (strchr(mode, '+')) {
        flag &= ~O_ACCMODE;
        flag |= O_RDWR;
    }
    if (flag & O_CREAT) mode_flg = 0644;

    int fd = open(path, flag, mode_flg);
    if (fd >= 0) {
        return fdopen(fd, mode);
    }
    return NULL;
}

FILE *fdopen(int fd, const char *mode __attribute__((unused))) {
    file_impl *fp = malloc(sizeof(file_impl));
    setup_fd_fp(fp, fd);
    return (FILE *) fp;
}

FILE *funopen(const void* cookie,
              int (*read_fn)(void*, char*, int),
              int (*write_fn)(void*, const char*, int),
              fpos_t (*seek_fn)(void*, fpos_t, int),
              int (*close_fn)(void*)) {
    file_impl *fp = malloc(sizeof(file_impl));
    fp->fd = -1;
    fp->cookie = (void *) cookie;
    fp->read_fn = read_fn;
    fp->write_fn = write_fn;
    fp->close_fn = close_fn;
    return (FILE *) fp;
}

int ferror(FILE *stream) {
    // We don't report any errors
    return 0;
}

#define fn_arg (fp->fd < 0 ? fp->cookie : ((void*)(intptr_t) fp->fd))

int fclose(FILE *stream) {
    file_impl *fp = (file_impl *) stream;
    int ret = 0;
    if (fp->close_fn)
        fp->close_fn(fn_arg);
    free(fp);
    return ret;
}

int fileno(FILE *stream) {
    file_impl *fp = (file_impl *) stream;
    return fp->fd;
}

int fputc(int ch, FILE *stream) {
    char c = ch;
    file_impl *fp = (file_impl *) stream;
    return fp->write_fn(fn_arg, &c, 1) >= 0 ? 0 : EOF;
}

int putchar(int ch) {
    return fputc(ch, stdout);
}

size_t fwrite(const void* buf, size_t size, size_t count, FILE* stream) {
    file_impl *fp = (file_impl *) stream;
    int len = size * count;
    int ret = fp->write_fn(fn_arg, buf, len);
    return ret == len ? count : 0;
}

int fputs(const char* s, FILE* stream) {
    file_impl *fp = (file_impl *) stream;
    size_t length = strlen(s);
    return fp->write_fn(fn_arg, s, length) == length ? 0 : EOF;
}

int fgetc(FILE *stream) {
    char ch;
    file_impl *fp = (file_impl *) stream;
    if (fp->read_fn(fn_arg, &ch, 1) == 1) {
        return ch;
    }
    return -1;
}

size_t fread(void *buf, size_t size, size_t count, FILE* stream) {
    file_impl *fp = (file_impl *) stream;
    int len = size * count;
    int ret = fp->read_fn(fn_arg, buf, len);
    return ret == len ? count : 0;
}

void setbuf(FILE* fp, char* buf) {}

// Internal functions for musl_vfscanf
// For now we only support buffer FILE pointers

void shlim(FILE *f, off_t lim) {
    file_impl *fp = (file_impl *) f;
    fp->buf->cnt = 0;
}

int shgetc(FILE *f) {
    file_impl *fp = (file_impl *) f;
    ++fp->buf->cnt;
    return *(const uint8_t *)(fp->buf->begin++);
}

size_t shcnt(FILE *f) {
    file_impl *fp = (file_impl *) f;
    return fp->buf->cnt;
}

void shunget(FILE *f) {
    file_impl *fp = (file_impl *) f;
    --fp->buf->begin;
}

// Original source: https://github.com/freebsd/freebsd/blob/master/contrib/file/src/getline.c
// License: BSD, full copyright notice please check original source
ssize_t getdelim(char **buf, size_t *bufsiz, int delimiter, FILE *fp) {
    char *ptr, *eptr;

    if (*buf == NULL || *bufsiz == 0) {
        *bufsiz = BUFSIZ;
        if ((*buf = (char *) malloc(*bufsiz)) == NULL)
            return -1;
    }

    for (ptr = *buf, eptr = *buf + *bufsiz;;) {
        int c = fgetc(fp);
        if (c == -1) {
            return ptr == *buf ? -1 : ptr - *buf;
        }
        *ptr++ = c;
        if (c == delimiter) {
            *ptr = '\0';
            return ptr - *buf;
        }
        if (ptr + 2 >= eptr) {
            char *nbuf;
            size_t nbufsiz = *bufsiz * 2;
            ssize_t d = ptr - *buf;
            if ((nbuf = (char *) realloc(*buf, nbufsiz)) == NULL)
                return -1;
            *buf = nbuf;
            *bufsiz = nbufsiz;
            eptr = nbuf + nbufsiz;
            ptr = nbuf + d;
        }
    }
}

ssize_t getline(char **buf, size_t *bufsiz, FILE *fp) {
    return getdelim(buf, bufsiz, '\n', fp);
}
