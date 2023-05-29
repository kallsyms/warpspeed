#ifndef COMMON_H
#define COMMON_H

#ifdef DEBUG
#define LOG(...) fprintf(stdout, __VA_ARGS__)
#else
#define LOG(...)
#endif

#endif
