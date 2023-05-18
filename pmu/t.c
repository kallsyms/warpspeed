#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>
#include <mach/mach.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
volatile static uint64_t ctr = 0;
static void profile_func(void *unused)
{
    srand(42);

    if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) < 0)
    {
        printf("Error: cannot set qos class.\n");
        return;
    }

    pthread_mutex_lock(&lock);
    printf("profile_func running\n");

    for (uint32_t i = 0; i < 1000000000; i++)
    {
        if (rand() % 2)
            ctr++;
    }
    printf("profile exit");
}

int main()
{
    pthread_mutex_lock(&lock);
    pthread_t work;
    if (pthread_create(&work, NULL, profile_func, NULL) != 0)
    {
        printf("Failed to create thread.\n");
        return 1;
    }
    mach_port_t thread_port = pthread_mach_thread_np(work);
    uint64_t ptid;
    if (pthread_threadid_np(work, &ptid) != 0)
    {
        printf("Failed to get thread id.\n");
        return 1;
    }

    pthread_mutex_unlock(&lock);

    uint64_t start_val;
    asm volatile("mrs %0, CNTPCT_EL0"
                 : "=r"(start_val));

    while (1)
    {
        uint64_t val;
        asm volatile("mrs %0, CNTPCT_EL0"
                     : "=r"(val));
        uint64_t diff = val - start_val;

        if (diff > 123456789)
        {
            if (thread_suspend(thread_port) != KERN_SUCCESS)
            {
                printf("Failed to suspend thread.\n");
                break;
            }
            printf("counter value after suspend: %llu\n", ctr);
            break;
        }
    }

    return 0;
}
