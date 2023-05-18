// Derived from https://gist.githubusercontent.com/ibireme/173517c208c7dc333ba962c1f0d67d12/raw/d2b76cf7f0518f456134e6081dbe92d43dd99916/kpc_demo.c

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <unistd.h>     // for usleep()
#include <dlfcn.h>      // for dlopen() and dlsym()
#include <sys/sysctl.h> // for sysctl()
#include <sys/kdebug.h> // for kdebug trace decode
#include <mach/mach.h>

#include "replay_test.h"

/// Get lightweight PET mode (not in kperf.framework).
static int kperf_lightweight_pet_get(u32 *enabled)
{
    if (!enabled)
        return -1;
    usize size = 4;
    return sysctlbyname("kperf.lightweight_pet", enabled, &size, NULL, 0);
}

/// Set lightweight PET mode (not in kperf.framework).
static int kperf_lightweight_pet_set(u32 enabled)
{
    return sysctlbyname("kperf.lightweight_pet", NULL, NULL, &enabled, 4);
}

static bool lib_inited = false;
static bool lib_has_err = false;
static char lib_err_msg[256];

static void *lib_handle_kperf = NULL;
static void *lib_handle_kperfdata = NULL;

static void lib_deinit(void)
{
    lib_inited = false;
    lib_has_err = false;
    if (lib_handle_kperf)
        dlclose(lib_handle_kperf);
    if (lib_handle_kperfdata)
        dlclose(lib_handle_kperfdata);
    lib_handle_kperf = NULL;
    lib_handle_kperfdata = NULL;
    for (usize i = 0; i < lib_nelems(lib_symbols_kperf); i++)
    {
        const lib_symbol *symbol = &lib_symbols_kperf[i];
        *symbol->impl = NULL;
    }
    for (usize i = 0; i < lib_nelems(lib_symbols_kperfdata); i++)
    {
        const lib_symbol *symbol = &lib_symbols_kperfdata[i];
        *symbol->impl = NULL;
    }
}

static bool lib_init(void)
{
#define return_err()        \
    do                      \
    {                       \
        lib_deinit();       \
        lib_inited = true;  \
        lib_has_err = true; \
        return false;       \
    } while (false)

    if (lib_inited)
        return !lib_has_err;

    // load dynamic library
    lib_handle_kperf = dlopen(lib_path_kperf, RTLD_LAZY);
    if (!lib_handle_kperf)
    {
        snprintf(lib_err_msg, sizeof(lib_err_msg),
                 "Failed to load kperf.framework, message: %s.", dlerror());
        return_err();
    }
    lib_handle_kperfdata = dlopen(lib_path_kperfdata, RTLD_LAZY);
    if (!lib_handle_kperfdata)
    {
        snprintf(lib_err_msg, sizeof(lib_err_msg),
                 "Failed to load kperfdata.framework, message: %s.", dlerror());
        return_err();
    }

    // load symbol address from dynamic library
    for (usize i = 0; i < lib_nelems(lib_symbols_kperf); i++)
    {
        const lib_symbol *symbol = &lib_symbols_kperf[i];
        *symbol->impl = dlsym(lib_handle_kperf, symbol->name);
        if (!*symbol->impl)
        {
            snprintf(lib_err_msg, sizeof(lib_err_msg),
                     "Failed to load kperf function: %s.", symbol->name);
            return_err();
        }
    }
    for (usize i = 0; i < lib_nelems(lib_symbols_kperfdata); i++)
    {
        const lib_symbol *symbol = &lib_symbols_kperfdata[i];
        *symbol->impl = dlsym(lib_handle_kperfdata, symbol->name);
        if (!*symbol->impl)
        {
            snprintf(lib_err_msg, sizeof(lib_err_msg),
                     "Failed to load kperfdata function: %s.", symbol->name);
            return_err();
        }
    }

    lib_inited = true;
    lib_has_err = false;
    return true;

#undef return_err
}

// -----------------------------------------------------------------------------
// kdebug utils
// -----------------------------------------------------------------------------

/// Clean up trace buffers and reset ktrace/kdebug/kperf.
/// @return 0 on success.
static int kdebug_reset(void)
{
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDREMOVE};
    return sysctl(mib, 3, NULL, NULL, NULL, 0);
}

/// Disable and reinitialize the trace buffers.
/// @return 0 on success.
static int kdebug_reinit(void)
{
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDSETUP};
    return sysctl(mib, 3, NULL, NULL, NULL, 0);
}

/// Set debug filter.
static int kdebug_setreg(kd_regtype *kdr)
{
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDSETREG};
    usize size = sizeof(kd_regtype);
    return sysctl(mib, 3, kdr, &size, NULL, 0);
}

/// Set maximum number of trace entries (kd_buf).
/// Only allow allocation up to half the available memory (sane_size).
/// @return 0 on success.
static int kdebug_trace_setbuf(int nbufs)
{
    int mib[4] = {CTL_KERN, KERN_KDEBUG, KERN_KDSETBUF, nbufs};
    return sysctl(mib, 4, NULL, NULL, NULL, 0);
}

/// Enable or disable kdebug trace.
/// Trace buffer must already be initialized.
/// @return 0 on success.
static int kdebug_trace_enable(bool enable)
{
    int mib[4] = {CTL_KERN, KERN_KDEBUG, KERN_KDENABLE, enable};
    return sysctl(mib, 4, NULL, 0, NULL, 0);
}

/// Retrieve trace buffer information from kernel.
/// @return 0 on success.
static int kdebug_get_bufinfo(kbufinfo_t *info)
{
    if (!info)
        return -1;
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDGETBUF};
    size_t needed = sizeof(kbufinfo_t);
    return sysctl(mib, 3, info, &needed, NULL, 0);
}

/// Retrieve trace buffers from kernel.
/// @param buf Memory to receive buffer data, array of `kd_buf`.
/// @param len Length of `buf` in bytes.
/// @param count Number of trace entries (kd_buf) obtained.
/// @return 0 on success.
static int kdebug_trace_read(void *buf, usize len, usize *count)
{
    if (count)
        *count = 0;
    if (!buf || !len)
        return -1;

    // Note: the input and output units are not the same.
    // input: bytes
    // output: number of kd_buf
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDREADTR};
    int ret = sysctl(mib, 3, buf, &len, NULL, 0);
    if (ret != 0)
        return ret;
    *count = len;
    return 0;
}

/// Block until there are new buffers filled or `timeout_ms` have passed.
/// @param timeout_ms timeout milliseconds, 0 means wait forever.
/// @param suc set true if new buffers filled.
/// @return 0 on success.
static int kdebug_wait(usize timeout_ms, bool *suc)
{
    if (timeout_ms == 0)
        return -1;
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDBUFWAIT};
    usize val = timeout_ms;
    int ret = sysctl(mib, 3, NULL, &val, NULL, 0);
    if (suc)
        *suc = !!val;
    return ret;
}

// -----------------------------------------------------------------------------
// Demo
// -----------------------------------------------------------------------------

#define EVENT_NAME_MAX 8
typedef struct
{
    const char *alias;                 /// name for print
    const char *names[EVENT_NAME_MAX]; /// name from pmc db
} event_alias;

/// Event names from /usr/share/kpep/<name>.plist
static const event_alias profile_events[] = {
    {"instructions", {
                         "FIXED_INSTRUCTIONS", // Apple A7-A15
                         "INST_RETIRED.ANY"    // Intel Yonah, Merom, Core 1th-10th
                     }},
    /* {"branches", { */
    /*                  "INST_BRANCH",                  // Apple A7-A15 */
    /*                  "BR_INST_RETIRED.ALL_BRANCHES", // Intel Core 1th-10th */
    /*                  "INST_RETIRED.ANY",             // Intel Yonah, Merom */
    /*              }}, */
};

static kpep_event *get_event(kpep_db *db, const event_alias *alias)
{
    for (usize j = 0; j < EVENT_NAME_MAX; j++)
    {
        const char *name = alias->names[j];
        if (!name)
            break;
        kpep_event *ev = NULL;
        if (kpep_db_event(db, name, &ev) == 0)
        {
            return ev;
        }
    }
    return NULL;
}

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
    // printf("profile_func running\n");

    for (u32 i = 0; i < 1000000000; i++)
    {
        if (rand() % 2)
            ctr++;
    }
    printf("profile exit");
}

void cleanup(int unused)
{
    // stop tracing
    kdebug_trace_enable(0);
    kdebug_reset();
    kperf_sample_set(0);
    kperf_lightweight_pet_set(0);

    // stop counting
    kpc_set_counting(0);
    kpc_set_thread_counting(0);
    kpc_force_all_ctrs_set(0);

    _exit(0);
}

int main(int argc, const char *argv[])
{
    int ret = 0;
    signal(SIGINT, cleanup);

    if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) < 0)
    {
        printf("Error: cannot set qos class.\n");
        return 1;
    }

    // load dylib
    if (!lib_init())
    {
        printf("Error: %s\n", lib_err_msg);
        return 1;
    }

    // check permission
    int force_ctrs = 0;
    if (kpc_force_all_ctrs_get(&force_ctrs))
    {
        printf("Permission denied, xnu/kpc requires root privileges.\n");
        return 1;
    }

    // load pmc db
    kpep_db *db = NULL;
    if ((ret = kpep_db_create(NULL, &db)))
    {
        printf("Error: cannot load pmc database: %d.\n", ret);
        return 1;
    }
    printf("loaded db: %s (%s)\n", db->name, db->marketing_name);
    printf("number of fixed counters: %zu\n", db->fixed_counter_count);
    printf("number of configurable counters: %zu\n", db->config_counter_count);
    printf("CPU tick frequency: %llu\n", (unsigned long long)kperf_tick_frequency());

    // create a config
    kpep_config *cfg = NULL;
    if ((ret = kpep_config_create(db, &cfg)))
    {
        printf("Failed to create kpep config: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    if ((ret = kpep_config_force_counters(cfg)))
    {
        printf("Failed to force counters: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }

    // get events
    const usize ev_count = sizeof(profile_events) / sizeof(profile_events[0]);
    kpep_event *ev_arr[ev_count] = {0};
    for (usize i = 0; i < ev_count; i++)
    {
        const event_alias *alias = profile_events + i;
        ev_arr[i] = get_event(db, alias);
        if (!ev_arr[i])
        {
            printf("Cannot find event: %s.\n", alias->alias);
            return 1;
        }
    }

    // add event to config
    for (usize i = 0; i < ev_count; i++)
    {
        kpep_event *ev = ev_arr[i];
        if ((ret = kpep_config_add_event(cfg, &ev, 0, NULL)))
        {
            printf("Failed to add event: %d (%s).\n",
                   ret, kpep_config_error_desc(ret));
            return 1;
        }
    }

    // prepare buffer and config
    u32 classes = 0;
    usize reg_count = 0;
    kpc_config_t regs[KPC_MAX_COUNTERS] = {0};
    usize counter_map[KPC_MAX_COUNTERS] = {0};
    if ((ret = kpep_config_kpc_classes(cfg, &classes)))
    {
        printf("Failed get kpc classes: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    if ((ret = kpep_config_kpc_count(cfg, &reg_count)))
    {
        printf("Failed get kpc count: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    if ((ret = kpep_config_kpc_map(cfg, counter_map, sizeof(counter_map))))
    {
        printf("Failed get kpc map: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    if ((ret = kpep_config_kpc(cfg, regs, sizeof(regs))))
    {
        printf("Failed get kpc registers: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }

    // set config to kernel
    if ((ret = kpc_force_all_ctrs_set(1)))
    {
        printf("Failed force all ctrs: %d.\n", ret);
        return 1;
    }
    if ((classes & KPC_CLASS_CONFIGURABLE_MASK) && reg_count)
    {
        if ((ret = kpc_set_config(classes, regs)))
        {
            printf("Failed set kpc config: %d.\n", ret);
            return 1;
        }
    }

    u32 counter_count = kpc_get_counter_count(classes);
    if (counter_count == 0)
    {
        printf("Failed no counter\n");
        return 1;
    }

    // XXX: begin setup of target thread
    pthread_mutex_lock(&lock);
    pthread_t work;
    if (pthread_create(&work, NULL, profile_func, NULL) != 0)
    {
        printf("Failed to create thread.\n");
        return 1;
    }
    mach_port_t thread_port = pthread_mach_thread_np(work);
    u64 ptid;
    if (pthread_threadid_np(work, &ptid) != 0)
    {
        printf("Failed to get thread id.\n");
        return 1;
    }

    // start counting
    if ((ret = kpc_set_counting(classes)))
    {
        printf("Failed set counting: %d.\n", ret);
        return 1;
    }
    if ((ret = kpc_set_thread_counting(classes)))
    {
        printf("Failed set thread counting: %d.\n", ret);
        return 1;
    }

    // action id and timer id
    u32 actionid = 1;
    u32 timerid = 1;

    // alloc action and timer ids
    if ((ret = kperf_action_count_set(KPERF_ACTION_MAX)))
    {
        printf("Failed set action count: %d.\n", ret);
    }
    if ((ret = kperf_timer_count_set(KPERF_TIMER_MAX)))
    {
        printf("Failed set timer count: %d.\n", ret);
    }

    // set what to sample: PMC per thread
    if ((ret = kperf_action_samplers_set(actionid, KPERF_SAMPLER_PMC_THREAD)))
    {
        printf("Failed set sampler type: %d.\n", ret);
    }
    // set filter process
    /* if ((ret = kperf_action_filter_set_by_task(actionid, mach_task_self()))) */
    /* { */
    /*     printf("Failed set filter pid: %d.\n", ret); */
    /* } */
    if ((ret = kperf_action_filter_set_by_pid(actionid, -1)))
    {
        printf("Failed set filter pid: %d.\n", ret);
    }

    // setup PET (Profile Every Thread), start sampler
    // 50us is the lowest we're getting with this
    // https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/osfmk/kperf/kptimer.c#L121
    u64 ns = 10000ul; // 10us
    u64 tick = kperf_ns_to_ticks(ns);
    if ((ret = kperf_timer_period_set(actionid, tick)))
    {
        printf("Failed set timer period: %d.\n", ret);
    }
    if ((ret = kperf_timer_action_set(actionid, timerid)))
    {
        printf("Failed set timer action: %d.\n", ret);
    }
    if ((ret = kperf_timer_pet_set(timerid)))
    {
        printf("Failed set timer PET: %d.\n", ret);
    }
    if ((ret = kperf_lightweight_pet_set(1)))
    {
        printf("Failed set lightweight PET: %d.\n", ret);
    }
    if ((ret = kperf_sample_set(1)))
    {
        printf("Failed start sample: %d.\n", ret);
    }

    // reset kdebug/ktrace
    if ((ret = kdebug_reset()))
    {
        printf("Failed reset kdebug: %d.\n", ret);
    }

    int nbufs = 1000000;
    if ((ret = kdebug_trace_setbuf(nbufs)))
    {
        printf("Failed setbuf: %d.\n", ret);
    }
    if ((ret = kdebug_reinit()))
    {
        printf("Failed init kdebug buffer: %d.\n", ret);
    }

    // set trace filter: only log PERF_KPC_DATA_THREAD
    kd_regtype kdr = {0};
    kdr.type = KDBG_VALCHECK;
    kdr.value1 = KDBG_EVENTID(DBG_PERF, PERF_KPC, PERF_KPC_DATA_THREAD);
    if ((ret = kdebug_setreg(&kdr)))
    {
        printf("Failed set kdebug filter: %d.\n", ret);
    }
    // start trace
    if ((ret = kdebug_trace_enable(1)))
    {
        printf("Failed enable kdebug trace: %d.\n", ret);
    }

    // XXX: let the function under test run
    pthread_mutex_unlock(&lock);

    // sample and get buffers
    usize buf_capacity = nbufs * 2;
    kd_buf *buf = (kd_buf *)malloc(sizeof(kd_buf) * buf_capacity);

    while (1)
    {
        // read trace buffer from kernel
        usize count = 0;
        kdebug_trace_read(buf, sizeof(kd_buf) * nbufs, &count);
        for (int i = 0; i < count; i++)
        {
            kd_buf *cur_buf = &buf[i];
            u32 debugid = cur_buf->debugid;
            u32 cls = KDBG_EXTRACT_CLASS(debugid);
            u32 subcls = KDBG_EXTRACT_SUBCLASS(debugid);
            u32 code = KDBG_EXTRACT_CODE(debugid);

            // keep only thread PMC data
            if (cls != DBG_PERF)
                continue;
            if (subcls != PERF_KPC)
                continue;
            if (code != PERF_KPC_DATA_THREAD)
                continue;
            u32 func = debugid & KDBG_FUNC_MASK;
            if (func != DBG_FUNC_START)
                continue;

            u64 val = cur_buf->arg1;
            u32 tid = cur_buf->arg5;

            if (tid != ptid)
                continue;

            printf("val %llu\n", val);

            if (val > 123456789)
            {
                if (thread_suspend(thread_port) != KERN_SUCCESS)
                {
                    printf("Failed to suspend thread.\n");
                    break;
                }
                printf("counter value after suspend: %llu\n", ctr);
                goto out;
            }
        }
    }

out:
    cleanup(0);
}