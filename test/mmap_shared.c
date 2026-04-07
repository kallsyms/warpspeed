#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void fail(const char* message) {
    perror(message);
    exit(1);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 2;
    }

    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        fail("open");
    }

    const size_t len = 0x1000;
    char* mapping1 = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping1 == MAP_FAILED) {
        fail("mmap1");
    }

    char* mapping2 = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping2 == MAP_FAILED) {
        fail("mmap2");
    }

    printf("initial:%.*s\n", 5, mapping1);

    mapping1[0] = 'X';
    if (msync(mapping1, len, MS_SYNC) != 0) {
        fail("msync");
    }

    if (pwrite(fd, "Y", 1, 1) != 1) {
        fail("pwrite");
    }

    if (fsync(fd) != 0) {
        fail("fsync");
    }

    printf("mapped:%.*s\n", 5, mapping2);

    char file_bytes[6] = {0};
    if (pread(fd, file_bytes, 5, 0) != 5) {
        fail("pread");
    }
    printf("file:%s\n", file_bytes);

    if (munmap(mapping1, len) != 0) {
        fail("munmap1");
    }
    if (munmap(mapping2, len) != 0) {
        fail("munmap2");
    }
    if (close(fd) != 0) {
        fail("close");
    }

    return 0;
}
