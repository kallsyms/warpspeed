#ifndef COMMON_H
#define COMMON_H

#ifdef DEBUG
#define LOG(...) fprintf(stdout, __VA_ARGS__)
#else
#define LOG(...)
#endif

#define HYP_ASSERT_SUCCESS(ret) do { \
    if ((hv_return_t)(ret) != HV_SUCCESS) { \
        LOG("%s:%d: %s = %x\n", __FILE__, __LINE__, #ret, (ret)); \
        abort(); \
    } \
} while (0)

#endif
