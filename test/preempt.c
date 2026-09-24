#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

#define THREADS 2
#define INCREMENTS 20000000

static volatile long counter;
static atomic_int go;

// Unsynchronized increments without syscalls: increments get lost wherever a thread is preempted
// between its load and store, so the total depends on exactly where preemptions happen.
static void *worker(void *arg) {
    (void)arg;
    while (!atomic_load(&go)) {
    }
    for (long i = 0; i < INCREMENTS; i++) {
        counter = counter + 1;
    }
    return NULL;
}

int main(void) {
    pthread_t threads[THREADS];
    for (int i = 0; i < THREADS; i++) {
        pthread_create(&threads[i], NULL, worker, NULL);
    }
    atomic_store(&go, 1);
    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("counter: %ld of %d\n", counter, THREADS * INCREMENTS);
    return 0;
}
