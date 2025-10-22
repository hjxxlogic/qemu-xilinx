/*
 * QEMU Memory Watch - Header
 */

#ifndef SYSEMU_MEMORY_WATCH_H
#define SYSEMU_MEMORY_WATCH_H

#include "hw/core/cpu.h"
#include "exec/hwaddr.h"

void memory_watch_init(void);
void memory_watch_check_access(CPUState *cpu, hwaddr paddr,
                               unsigned size, bool is_write);
void memory_watch_cleanup(void);

#endif
