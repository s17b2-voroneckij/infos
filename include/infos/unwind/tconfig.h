/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#define ATTRIBUTE_UNUSED __attribute__((unused))

#define EH_RETURN_STACKADJ_RTX 1

#include "unwind-pnacl.h"

#define NULL 0
#define alloca(size) __builtin_alloca (size)

typedef unsigned long size_t;
#ifdef __cplusplus
extern "C" {
#endif
void abort();

void gcc_assert(int a);

void puts(const char* ptr);

void *memcpy(void *dest, const void *src, size_t n);

void *memset(void *s, int c, size_t n);

void* malloc(size_t size);

void free(void* ptr);

void gcc_unreachable();

#ifdef __cplusplus
}
#endif
