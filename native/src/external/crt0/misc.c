#include <sys/auxv.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

// errno

static int g_errno = 0;

int *__errno(void) {
    return &g_errno;
}

long __set_errno_internal(int n) {
    g_errno = n;
    return -1;
}

// Source: bionic/libc/bionic/libgen.cpp
static int __basename_r(const char *path, char* buffer, size_t buffer_size) {
    const char *startp = NULL;
    const char *endp = NULL;
    int len;
    int result;

    // Empty or NULL string gets treated as ".".
    if (path == NULL || *path == '\0') {
        startp = ".";
        len = 1;
        goto Exit;
    }

    // Strip trailing slashes.
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/') {
        endp--;
    }

    // All slashes becomes "/".
    if (endp == path && *endp == '/') {
        startp = "/";
        len = 1;
        goto Exit;
    }

    // Find the start of the base.
    startp = endp;
    while (startp > path && *(startp - 1) != '/') {
        startp--;
    }

    len = endp - startp +1;

Exit:
    result = len;
    if (buffer == NULL) {
        return result;
    }
    if (len > (int) buffer_size - 1) {
        len = buffer_size - 1;
        result = -1;
        errno = ERANGE;
    }

    if (len >= 0) {
        memcpy(buffer, startp, len);
        buffer[len] = 0;
    }
    return result;
}

char *basename(const char *path) {
    static char buf[4069];
    int rc = __basename_r(path, buf, sizeof(buf));
    return (rc < 0) ? NULL : buf;
}

// Simply just abort when abort_message is called
void __wrap_abort_message(const char* format, ...) {
    abort();
}

typedef struct at_exit_func {
    void *arg;
    void (*func)(void*);
} at_exit_func;

static int at_exit_cap = 0;
static int at_exit_sz = 0;
static at_exit_func *at_exit_list = NULL;

int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle) {
    if (at_exit_sz == at_exit_cap) {
        at_exit_cap = at_exit_cap ? at_exit_sz * 2 : 16;
        at_exit_list = realloc(at_exit_list, at_exit_cap * sizeof(at_exit_func));
    }
    at_exit_list[at_exit_sz].func = func;
    at_exit_list[at_exit_sz].arg = arg;
    ++at_exit_sz;
    return 0;
}

typedef void fini_func_t(void);

extern fini_func_t *__fini_array_start[];
extern fini_func_t *__fini_array_end[];

void exit(int status) {
    // Call registered at_exit functions in reverse
    for (int i = at_exit_sz - 1; i >= 0; --i) {
        at_exit_list[i].func(at_exit_list[i].arg);
    }

    fini_func_t** array = __fini_array_start;
    size_t count = __fini_array_end - __fini_array_start;
    // Call fini functions in reverse order
    while (count-- > 0) {
        fini_func_t* function = array[count];
        (*function)();
    }

    _exit(status);
}

// Emulate pthread functions

typedef struct key_data {
    void *data;
    void (*dtor)(void*);
    int used;
} key_data;

static pthread_key_t key_list_sz = 0;
static key_data *key_list;

int pthread_key_create(pthread_key_t *key_ptr, void (*dtor)(void*)) {
    if (key_list_sz == 0) {
        key_list_sz = 16;
        key_list = calloc(key_list_sz, sizeof(key_data));
    }

    pthread_key_t k = 0;

    // Find an empty slot
    for (; k < key_list_sz; ++k) {
        if (!key_list[k].used) {
            goto set_key;
        }
    }
    // Expand list
    key_list_sz *= 2;
    key_list = realloc(key_list, key_list_sz * sizeof(key_data));
    memset(&key_list[k], 0, k * sizeof(key_data));

set_key:
    *key_ptr = k;
    key_list[k].used = 1;
    key_list[k].dtor = dtor;
    return 0;
}

int pthread_key_delete(pthread_key_t key) {
    if (key < key_list_sz) {
        if (key_list[key].dtor && key_list[key].data) {
            key_list[key].dtor(key_list[key].data);
        }
        key_list[key].data = NULL;
        key_list[key].dtor = NULL;
        key_list[key].used = 0;
    }
    return 0;
}

void *pthread_getspecific(pthread_key_t key) {
    if (key >= key_list_sz || !key_list[key].used) {
        return NULL;
    }
    return key_list[key].data;
}

int pthread_setspecific(pthread_key_t key, const void *value) {
    if (key >= key_list_sz || !key_list[key].used) {
        errno = EINVAL;
        return 1;
    }
    key_list[key].data = (void *) value;
    return 0;
}

int getpagesize() {
    static int sz = 0;
    if (sz == 0) {
        sz = getauxval(AT_PAGESZ);
    }
    return sz;
}

// Stack protector support

uintptr_t __stack_chk_guard = 0;

void __stack_chk_fail() {
    abort();
}
