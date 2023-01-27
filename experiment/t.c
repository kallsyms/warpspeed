#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/arm/thread_status.h>

void child()
{
    char c;
    read(0, &c, 1);
    puts("bye\n");
    exit(0);
}

void error(char *msg)
{
        printf("[!] error: %s.\n",msg);
        exit(1);
}

int main(int argc, char **argv)
{
    pid_t pid = fork();
    if (pid == 0) {
        child();
    } else {
        printf("child: %d\n", pid);
        sleep(1);
        kill(pid, SIGSTOP);

        arm_thread_state64_t state;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        printf("%d\n", sc);
        long thread = 0;        // for first thread
        thread_act_port_array_t thread_list;
        mach_msg_type_number_t thread_count;
        task_t  port;

        if(task_for_pid(mach_task_self(), pid, &port))
                error("cannot get port");

        if(task_threads(port, &thread_list, &thread_count))
                error("cannot get list of tasks");
        
        printf("tl[t] = %d\n", thread_list[thread]);

        if(thread_get_state(
                          thread_list[thread],
                          ARM_THREAD_STATE64,
                          (thread_state_t)&state,
                          &sc
        )) error("getting state from thread");

        for (int i = 0; i < 29; i++) {
            printf("x%d: 0x%llx\n", i, state.__x[i]);
        }
    }

    return 0;
}
