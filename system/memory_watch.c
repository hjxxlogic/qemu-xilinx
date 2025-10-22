/*
 * QEMU Memory Watch - Integrated Version
 * 监测Windows对xHCI设备上下文的物理内存访问
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/thread.h"
#include "hw/core/cpu.h"
#include "sysemu/memory_watch.h"
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/xhci_context_monitor.sock"
#define LOG_PATH "/tmp/qemu_memory_watch.log"

static int sock_fd = -1;
static FILE *log_file = NULL;
static GHashTable *watched_addresses = NULL;
static QemuMutex watch_lock;
static uint64_t access_count = 0;
static bool initialized = false;

typedef struct {
    uint64_t start;
    uint64_t end;
    char type[32];
    int slot_id;
} WatchRange;

static int connect_to_rtl(void)
{
    struct sockaddr_un addr;
    int fd;
    
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    g_strlcpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path));
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        return fd;
    }
    
    close(fd);
    return -1;
}

static void log_access(const char *op, uint64_t addr, unsigned size,
                      const char *type, int slot_id, unsigned int cpu)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    if (log_file) {
        fprintf(log_file, "[%ld.%06ld] CPU%u %s 0x%016" PRIx64 " size=%u type=%s slot=%d\n",
                (long)tv.tv_sec, (long)tv.tv_usec, cpu, op, addr, size, type, slot_id);
        fflush(log_file);
    }
}

static void process_watch_command(const char *cmd)
{
    char type[32];
    int slot_id;
    uint64_t addr;
    int size;
    
    if (sscanf(cmd, "WATCH %31s %d 0x%" PRIx64 " %d",
              type, &slot_id, &addr, &size) == 4) {
        
        qemu_mutex_lock(&watch_lock);
        
        if (!g_hash_table_contains(watched_addresses, GUINT_TO_POINTER(addr))) {
            WatchRange *range = g_new(WatchRange, 1);
            range->start = addr;
            range->end = addr + 64;
            g_strlcpy(range->type, type, sizeof(range->type));
            range->slot_id = slot_id;
            
            g_hash_table_insert(watched_addresses, GUINT_TO_POINTER(addr), range);
            
            if (log_file) {
                fprintf(log_file, "# Watching: %s Slot=%d Addr=0x%016" PRIx64 "\n",
                        type, slot_id, addr);
                fflush(log_file);
            }
        }
        
        qemu_mutex_unlock(&watch_lock);
    }
}

static void check_socket_data(void)
{
    char buffer[512];
    ssize_t n;
    static uint64_t reconnect_counter = 0;
    
    // 如果未连接，每1000次尝试重新连接一次
    if (sock_fd < 0) {
        reconnect_counter++;
        if (reconnect_counter >= 1000) {
            reconnect_counter = 0;
            sock_fd = connect_to_rtl();
            if (sock_fd >= 0 && log_file) {
                fprintf(log_file, "# Connected to RTL socket\n\n");
                fflush(log_file);
                fprintf(stderr, "[Memory Watch] Connected to RTL\n");
            }
        }
        return;
    }
    
    n = recv(sock_fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
    if (n > 0) {
        buffer[n] = '\0';
        process_watch_command(buffer);
    } else if (n == 0) {
        close(sock_fd);
        sock_fd = -1;
        if (log_file) {
            fprintf(log_file, "# RTL disconnected\n");
            fflush(log_file);
        }
    }
}

void memory_watch_check_access(CPUState *cpu, hwaddr paddr, 
                               unsigned size, bool is_write)
{
    if (!initialized || !watched_addresses) {
        return;
    }
    
    static int check_counter = 0;
    if (++check_counter >= 1000) {
        check_socket_data();
        check_counter = 0;
    }
    
    qemu_mutex_lock(&watch_lock);
    
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, watched_addresses);
    
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        WatchRange *range = (WatchRange *)value;
        
        if (paddr >= range->start && paddr < range->end) {
            const char *op = is_write ? "WRITE" : "READ";
            unsigned int cpu_index = cpu ? cpu->cpu_index : 0;
            
            log_access(op, paddr, size, range->type, range->slot_id, cpu_index);
            
            access_count++;
            break;
        }
    }
    
    qemu_mutex_unlock(&watch_lock);
}

void memory_watch_init(void)
{
    if (initialized) {
        return;
    }
    
    log_file = fopen(LOG_PATH, "w");
    if (!log_file) {
        return;
    }
    
    fprintf(log_file, "# QEMU Memory Watch (Integrated)\n");
    fprintf(log_file, "# Format: [TIMESTAMP] CPU OP ADDR SIZE TYPE SLOT\n\n");
    
    qemu_mutex_init(&watch_lock);
    watched_addresses = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             NULL, g_free);
    
    sock_fd = connect_to_rtl();
    if (sock_fd >= 0) {
        fprintf(log_file, "# Connected to RTL socket\n\n");
    } else {
        fprintf(log_file, "# Warning: Not connected to RTL\n\n");
    }
    
    fflush(log_file);
    initialized = true;
}

void memory_watch_cleanup(void)
{
    if (!initialized) {
        return;
    }
    
    qemu_mutex_lock(&watch_lock);
    
    if (log_file) {
        fprintf(log_file, "\n# Memory Watch Statistics\n");
        fprintf(log_file, "# Total memory accesses detected: %" PRIu64 "\n", access_count);
        fprintf(log_file, "# Watched addresses: %u\n",
                g_hash_table_size(watched_addresses));
        fclose(log_file);
        log_file = NULL;
    }
    
    if (watched_addresses) {
        g_hash_table_destroy(watched_addresses);
        watched_addresses = NULL;
    }
    
    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
    
    qemu_mutex_unlock(&watch_lock);
    initialized = false;
}
