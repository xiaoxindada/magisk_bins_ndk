#include <stdlib.h>

#include "stdio_impl.h"
#include "printf/printf.h"

// tiny_vfprintf implementation

static void fct_putchar(char ch, void *p) {
    fputc(ch, (FILE *) p);
}

int tiny_vfprintf(FILE *stream, const char *format, va_list arg) {
    return vfctprintf(fct_putchar, stream, format, arg);
}

// {s,f}printf family wrappers

int vasprintf(char **strp, const char *fmt, va_list ap) {
    int size = vsnprintf(NULL, 0, fmt, ap);
    if (size >= 0) {
        *strp = malloc(size + 1);
        vsnprintf(*strp, size, fmt, ap);
    }
    return size;
}

int vsprintf(char *str, const char *fmt, va_list ap) {
    file_impl file;
    buf_holder h;
    h.begin = str;
    h.end = NULL;
    setup_buf_fp(&file, &h);

    int retval = vfprintf((FILE *) &file, fmt, ap);
    if (retval > 0) {
        str[retval] = '\0';
    }
    return retval;
}

int sprintf(char *str, const char *format, ...) {
    va_list ap;
    int retval;

    va_start(ap, format);
    retval = vsprintf(str, format, ap);
    va_end(ap);
    return retval;
}

int vsnprintf(char *str, size_t size, const char *fmt, va_list ap) {
    file_impl file;
    buf_holder h;
    h.begin = str;
    h.end = str + size;
    setup_buf_fp(&file, &h);

    int retval = vfprintf((FILE *) &file, fmt, ap);
    if (retval > 0) {
        str[MIN(size - 1, retval)] = '\0';
    }
    return retval;
}

int snprintf(char *str, size_t size, const char *format, ...) {
    va_list ap;
    int retval;

    va_start(ap, format);
    retval = vsnprintf(str, size, format, ap);
    va_end(ap);
    return retval;
}

int vprintf(const char *fmt, va_list args) {
    return vfprintf(stdout, fmt, args);
}

int fprintf(FILE *stream, const char *fmt, ...) {
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vfprintf(stream, fmt, args);
    va_end(args);
    return ret;
}

int printf(const char *fmt, ...) {
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vfprintf(stdout, fmt, args);
    va_end(args);
    return ret;
}

// sscanf family

int musl_vfscanf(FILE *f, const char *fmt, va_list ap);

int vsscanf(const char *s, const char *fmt, va_list args) {
    file_impl file;
    buf_holder h;
    h.begin = (void *) s;
    h.end = NULL;
    setup_buf_fp(&file, &h);
    return musl_vfscanf((FILE *) &file, fmt, args);
}

int sscanf(const char *str, const char *format, ...) {
    va_list ap;
    int retval;

    va_start(ap, format);
    retval = vsscanf(str, format, ap);
    va_end(ap);
    return retval;
}
