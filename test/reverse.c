#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

volatile long value;

__attribute__((noinline)) void set_value(long v) {
    value = v;
}

// Somewhere to put breakpoints that are never hit.
__attribute__((noinline)) void never_called(void) {
    value = 1;
    value = 2;
    value = 3;
    value = 4;
    value = 5;
    value = 6;
    value = 7;
    value = 8;
}

static void busy(void) {
    volatile long sum = 0;
    for (long i = 0; i < 5000000; i++) {
        sum += i;
    }
}

int main(void) {
    printf("value=%p set_value=%p never_called=%p\n", (void *)&value, (void *)set_value,
           (void *)never_called);
    fflush(stdout);
    int fd = open("/dev/null", O_WRONLY);
    for (long i = 1; i <= 5; i++) {
        busy();
        set_value(i);
        write(fd, (const void *)&value, sizeof(value));
    }
    printf("done %ld\n", value);
    return 0;
}
