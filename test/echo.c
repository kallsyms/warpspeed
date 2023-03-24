#include <stdio.h>
#include <unistd.h>

int main() {
    puts("input:");
    char data[5] = {0};
    data[read(0, data, 4)] = 0;
    printf("got: %s\n", data);
    puts("bye");
    return 0;
}
