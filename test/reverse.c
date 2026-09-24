#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

volatile long value;

__attribute__((noinline)) void set_value(long v) {
    value = v;
}

static void busy(void) {
    volatile long sum = 0;
    for (long i = 0; i < 5000000; i++) {
        sum += i;
    }
}

int main(void) {
    printf("value=%p set_value=%p\n", (void *)&value, (void *)set_value);
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
