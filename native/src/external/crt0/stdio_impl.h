#pragma once

#include <stdio.h>

#define MIN(a,b) ((a)<(b) ? (a) : (b))

typedef struct buf_holder {
    void *begin;
    void *end;
    size_t cnt;
} buf_holder;

typedef struct file_impl {
    int fd;
    union {
        void *cookie;
        buf_holder *buf;
    };
    int (*read_fn)(void*, char*, int);
    int (*write_fn)(void*, const char*, int);
    int (*close_fn)(void*);
} file_impl;

void setup_fd_fp(file_impl *fp, int fd);
void setup_buf_fp(file_impl *fp, buf_holder *h);
