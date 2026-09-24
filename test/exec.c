#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2) {
        int fd = atoi(argv[1]);
        printf("after exec: fd %s\n", fcntl(fd, F_GETFD) < 0 ? "closed" : "open");
        return 0;
    }
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    printf("before exec\n");
    fflush(stdout);
    char arg[16];
    snprintf(arg, sizeof(arg), "%d", fd);
    execl(argv[0], argv[0], arg, NULL);
    perror("execl");
    return 1;
}
