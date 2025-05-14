#include <string.h>
#include <malloc.h>

void *memset(void *dst, int ch, size_t n) {
    uint8_t *d = dst;
    uint8_t c = ch;
    while (n--)
        (*d++) = c;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    if (dst < src) {
        return memcpy(dst, src, n);
    }
    // Copy backwards
    uint8_t *d = dst + n;
    const uint8_t *s = src + n;
    while (n--)
        *--d = *--s;
    return dst;
}

void *memcpy(void * restrict dst, const void * restrict src, size_t n) {
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--)
        *d++ = *s++;
    return dst;
}

int memcmp(const void *lhs, const void *rhs, size_t n) {
    const uint8_t *l = lhs;
    const uint8_t *r = rhs;
    while (n--) {
        if (*l != *r) {
            return *l - *r;
        } else {
            l++;
            r++;
        }
    }
    return 0;
}

void *memchr(const void *ptr, int ch, size_t n) {
    const uint8_t *p = ptr;
    uint8_t c = ch;
    while (n--) {
        if (*p != c)
            ++p;
        else
            return (void *) p;
    }
    return NULL;
}

char *strchr(const char *s, int ch) {
    char c = ch;
    while (*s != c)
        if (!*s++)
            return NULL;
    return (char *) s;
}

char *strrchr(const char *s, int ch) {
    char c = ch;
    const char *ret = NULL;
    do {
        if(*s == c)
            ret = s;
    } while(*s++);
    return (char *) ret;
}

int strcmp(const char *lhs, const char *rhs) {
    while (*lhs && (*lhs == *rhs)) {
        ++lhs;
        ++rhs;
    }
    return *(uint8_t *)lhs - *(uint8_t *)rhs;
}

size_t strlen(const char *str) {
    size_t l = 0;
    while (str[l])
        ++l;
    return l;
}

size_t strnlen(const char *s, size_t maxlen) {
    size_t l = 0;
    while (l < maxlen && s[l])
        ++l;
    return l;
}

char *strcpy(char *restrict dest, const char *restrict src) {
    char *ret = dest;
    while ((*dest++ = *src++)) {}
    return ret;
}

char *strdup(const char *str) {
    size_t siz;
    char *copy;
    siz = strlen(str) + 1;
    if ((copy = malloc(siz)) == NULL)
        return NULL;
    memcpy(copy, str, siz);
    return copy;
}
