#include "kpc.h"

int kperf_lightweight_pet_get(u32 *enabled)
{
    if (!enabled)
        return -1;
    usize size = 4;
    return sysctlbyname("kperf.lightweight_pet", enabled, &size, NULL, 0);
}

int kperf_lightweight_pet_set(u32 enabled)
{
    return sysctlbyname("kperf.lightweight_pet", NULL, NULL, &enabled, 4);
}

const char *kpep_config_error_desc(int code)
{
    if (0 <= code && code < KPEP_CONFIG_ERROR_MAX)
    {
        return kpep_config_error_names[code];
    }
    return "unknown error";
}

static bool lib_inited = false;
static bool lib_has_err = false;
static char lib_err_msg[256];

static void *lib_handle_kperf = NULL;
static void *lib_handle_kperfdata = NULL;

__attribute__((destructor)) static void lib_deinit(void)
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

__attribute__((constructor)) static bool lib_init(void)
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

int kdebug_reset(void)
{
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDREMOVE};
    return sysctl(mib, 3, NULL, NULL, NULL, 0);
}

int kdebug_reinit(void)
{
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDSETUP};
    return sysctl(mib, 3, NULL, NULL, NULL, 0);
}

int kdebug_setreg(kd_regtype *kdr)
{
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDSETREG};
    usize size = sizeof(kd_regtype);
    return sysctl(mib, 3, kdr, &size, NULL, 0);
}

int kdebug_trace_setbuf(int nbufs)
{
    int mib[4] = {CTL_KERN, KERN_KDEBUG, KERN_KDSETBUF, nbufs};
    return sysctl(mib, 4, NULL, NULL, NULL, 0);
}

int kdebug_trace_enable(bool enable)
{
    int mib[4] = {CTL_KERN, KERN_KDEBUG, KERN_KDENABLE, enable};
    return sysctl(mib, 4, NULL, 0, NULL, 0);
}

int kdebug_get_bufinfo(kbufinfo_t *info)
{
    if (!info)
        return -1;
    int mib[3] = {CTL_KERN, KERN_KDEBUG, KERN_KDGETBUF};
    size_t needed = sizeof(kbufinfo_t);
    return sysctl(mib, 3, info, &needed, NULL, 0);
}

int kdebug_trace_read(void *buf, usize len, usize *count)
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

int kdebug_wait(usize timeout_ms, bool *suc)
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

kpep_event *get_event(kpep_db *db, const event_alias *alias)
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