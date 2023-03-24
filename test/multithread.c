#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <sys/wait.h>

void *child_f(void *unused) {
	puts("child1!");
	puts("child2!");
	puts("child3!");
	return NULL;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		puts("Usage: __ fork|pthread");
		return 1;
	}
	
	printf("i am %d\n", getpid());
	char c;
	read(0, &c, 1);

	if (!strcmp(argv[1], "fork")) {
		pid_t child = fork();
		if (child == 0) {
			child_f(NULL);
			return 0;
		} else {
			printf("child: %d\n", child);
			waitpid(child, NULL, 0);
			return 0;
		}
	} else if (!strcmp(argv[1], "pthread")) {
		pthread_t th;
		pthread_create(&th, NULL, child_f, NULL);
		//while (1) {}
		puts("before join");
		pthread_join(th, NULL);
		puts("after join");
		return 0;
	} else {
		printf("Unrecognized mt: %s", argv[1]);
		return 1;
	}
}
