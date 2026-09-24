#include <dispatch/dispatch.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define THREADS 4
#define ROUNDS 5

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static char order[THREADS * ROUNDS + 1];
static int next;

static void *worker(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < ROUNDS; i++) {
        // Different lengths, so which thread gets the lock next depends on timing.
        usleep(1500 * (id + 1) * (i % 3 + 1));
        pthread_mutex_lock(&lock);
        order[next++] = '0' + id;
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int main(void) {
    pthread_t threads[THREADS];
    for (long i = 0; i < THREADS; i++) {
        pthread_create(&threads[i], NULL, worker, (void *)i);
    }
    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("order: %s\n", order);

    dispatch_queue_t global = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
    dispatch_queue_t serial = dispatch_queue_create("warpspeed.serial", NULL);
    dispatch_group_t group = dispatch_group_create();
    __block int sum = 0;
    for (int i = 1; i <= 10; i++) {
        dispatch_group_async(group, global, ^{
            usleep(50 * i);
            dispatch_sync(serial, ^{
                sum += i;
            });
        });
    }
    dispatch_group_enter(group);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_MSEC), serial, ^{
        sum += 100;
        dispatch_group_leave(group);
    });
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    printf("sum: %d\n", sum);
    return 0;
}
