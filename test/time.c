#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern uint64_t mytime();
extern uint64_t mach_absolute_time();

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s comm|syscall", argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "comm")) {
        printf("The current time is: %lld\n", mach_absolute_time());
    } else if (!strcmp(argv[1], "syscall")) {
        printf("The current time is: %lld\n", mytime());
    } else {
        fprintf(stderr, "Usage: %s comm|syscall", argv[0]);
        return 1;
    }
	return 0;
}
