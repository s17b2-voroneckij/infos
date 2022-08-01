#include <infos/unwind/tconfig.h>

void gcc_assert(int a) {}

char MEMORY[4096 * 50];

void* malloc(size_t size) {
	static char* freeMemoryBase = MEMORY;
	size = (size + 7) / 8 * 8;
	freeMemoryBase += size;
	return freeMemoryBase - size;
}

void free(void* ptr) {}

void gcc_unreachable() {}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2 && *s1 == *s2) {
        s1++;
        s2++;
    }
    if (!*s1 && *s2) return -1;
    if (!*s2 && *s1) return 1;
    if (!*s1 && !*s2) return 0;
    return *s1 - *s2;
}

void abort() {}

size_t strlen(const char* ptr) {
    size_t result = 0;
    while (*ptr) {
        result++;
        ptr++;
    }
    return result;
}