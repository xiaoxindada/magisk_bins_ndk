#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BLOCK_SIZE (1 << 22)  /* 4M */
#define MMAP_THRESHOLD (1 << 18)  /* 256k */
#define WORD_SZ (sizeof(void*))
#define MIN_ALIGNMENT (2 * WORD_SZ)

#define CHUNK_START(p) *((void **)(p - WORD_SZ))
#define CHUNK_SIZE(p)  *((size_t *) CHUNK_START(p))

#define sys_alloc(s) mmap(NULL, s, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)

/*
 * Allocated memory chunk layout
 *
 * +-------------+ <----------- chunk_start
 * | chunk_size  | size_t
 * +-------------+
 * | padding     | n words (n can be 0)
 * +-------------+
 * | chunk_start | void *
 * +-------------+ <----------- data_start
 * | data        | chunk_size
 * +-------------+
 *
 */

static inline size_t align(size_t l, size_t align) {
    return (l + align - 1) / align * align;
}

// Prefix is chunk_size + padding + chunk_start
static size_t calculate_prefix(size_t start, size_t alignment) {
    size_t p = start;
    // Reserve 2 words, one for chunk_size, one for chunk_start
    p += 2 * WORD_SZ;
    p = align(p, alignment);
    return p - start;
}

void *memalign(size_t alignment, size_t size) {
    static struct {
        void *curr;
        void *end;
    } block = { NULL, NULL };

    if (alignment < MIN_ALIGNMENT) alignment = MIN_ALIGNMENT;
    if (alignment > getpagesize()) alignment = getpagesize();
    size = align(size, MIN_ALIGNMENT);

    if (size >= MMAP_THRESHOLD) {
        size_t prefix = calculate_prefix(0, alignment);
        void *chunk = sys_alloc(size + prefix);
        if (chunk == MAP_FAILED) {
            errno = ENOMEM;
            return NULL;
        }
        void *p = chunk + prefix;
        CHUNK_START(p) = chunk;
        CHUNK_SIZE(p) = size;
        return p;
    }

    size_t prefix = calculate_prefix((size_t) block.curr, alignment);
    if (block.curr == NULL || block.curr + prefix + size > block.end) {
        void *b = sys_alloc(BLOCK_SIZE);
        if (b == MAP_FAILED) {
            errno = ENOMEM;
            return NULL;
        }
        block.curr = b;
        block.end = b + BLOCK_SIZE;
        prefix = calculate_prefix((size_t) b, alignment);
    }

    void *p = block.curr + prefix;
    CHUNK_START(p) = block.curr;
    CHUNK_SIZE(p) = size;
    block.curr += prefix + size;
    return p;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    void *ptr = memalign(alignment, size);
    if (ptr) {
        *memptr = ptr;
        return 0;
    } else {
        return ENOMEM;
    }
}

void *malloc(size_t size) {
    return memalign(MIN_ALIGNMENT, size);
}

void free(void *ptr) {
    if (ptr == NULL) return;
    size_t size = CHUNK_SIZE(ptr);
    if (size >= MMAP_THRESHOLD) {
        munmap(CHUNK_START(ptr), size);
    }
}

void *crt0_calloc(size_t nmemb, size_t size) {
    size_t sz;
    if (__builtin_mul_overflow(nmemb, size, &sz)) {
        errno = ENOMEM;
        return NULL;
    }
    return malloc(sz);
}

// For some reason calloc does not export properly
__asm__(".global calloc \n calloc = crt0_calloc");

void *realloc(void *ptr, size_t size) {
    if (ptr) {
        size_t old_sz = CHUNK_SIZE(ptr);
        if (old_sz >= size)
            return ptr;
        void *p = malloc(size);
        memcpy(p, ptr, old_sz);
        free(ptr);
        return p;
    } else {
        return malloc(size);
    }
}

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
    size_t sz;
    if (__builtin_mul_overflow(nmemb, size, &sz)) {
        errno = ENOMEM;
        return NULL;
    }
    return realloc(ptr, sz);
}
