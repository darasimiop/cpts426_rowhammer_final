#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>

#define BUFFER_SIZE (256 * 1024 * 1024) // 256MB

void flush(void* addr) {
    _mm_clflush(addr);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <init_value_hex> <hammer_count> <test_count>\n", argv[0]);
        return 1;
    }

    uint8_t init_value = (uint8_t)strtol(argv[1], NULL, 16);
    int hammer_count = atoi(argv[2]);
    int test_count = atoi(argv[3]);

    printf("[*] Allocating %dMB of memory...\n", BUFFER_SIZE / (1024 * 1024));
    uint8_t* buffer = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (buffer == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("[*] Initializing buffer with 0x%02X...\n", init_value);
    memset(buffer, init_value, BUFFER_SIZE);

    srand(time(NULL));
    for (int t = 0; t < test_count; ++t) {
        size_t offset = (rand() % (BUFFER_SIZE - 128));
        volatile uint8_t* a = buffer + offset;
        volatile uint8_t* b = buffer + offset + 64;

        printf("[*] Test %d: hammering addresses %p and %p...\n", t + 1, a, b);

        for (int i = 0; i < hammer_count; ++i) {
            *a;
            *b;
            flush((void*)a);
            flush((void*)b);
        }

        // Check for flips
        if (a[0] != init_value || b[0] != init_value) {
            printf("[!!] Bit flip detected at offset %zu\n", offset);
            printf("     a[0] = 0x%02X, b[0] = 0x%02X\n", a[0], b[0]);
        } else {
            printf("[OK] No bit flip at this location.\n");
        }
    }

    munmap(buffer, BUFFER_SIZE);
    return 0;
}
