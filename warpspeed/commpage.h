// https://github.com/darlinghq/darling/blob/master/src/startup/mldr/commpage.h
#ifndef _COMMPAGE_H
#define _COMMPAGE_H
#include <stdbool.h>
#include <stdint.h>

// Include commpage definitions
#define PRIVATE
#define _COMM_PAGE_LAYOUT_VERSION 0  // ghost: force non RO page pointers
#include "cpu_capabilities.h"

#ifdef __cplusplus
extern "C" {
#endif

void commpage_setup(uint8_t *commpage);

#ifdef __cplusplus
}
#endif

#endif

