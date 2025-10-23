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
static volatile bool enabled = false;  // volatile for lock-free read

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
    uint64_t addr;
    int size;
    
    // 解析: "WATCH 0x<ADDR> <SIZE>\n"
    if (sscanf(cmd, "WATCH 0x%" PRIx64 " %d", &addr, &size) == 2) {
        
        qemu_mutex_lock(&watch_lock);
        
        bool success = false;
        if (!g_hash_table_contains(watched_addresses, GUINT_TO_POINTER(addr))) {
            WatchRange *range = g_new(WatchRange, 1);
            range->start = addr;
            range->end = addr + size;
            g_strlcpy(range->type, "CONTEXT", sizeof(range->type));
            range->slot_id = 0;
            
            g_hash_table_insert(watched_addresses, GUINT_TO_POINTER(addr), range);
            
            if (log_file) {
                fprintf(log_file, "# Watching: Addr=0x%016" PRIx64 " Size=%d\n",
                        addr, size);
                fflush(log_file);
            }
            success = true;
        } else {
            // 地址已经在监测列表中
            success = true;
        }
        
        qemu_mutex_unlock(&watch_lock);
        
        // 发送回复
        const char *reply = success ? "OK\n" : "ERROR\n";
        send(sock_fd, reply, strlen(reply), 0);
    } else {
        // 解析失败，发送ERROR
        const char *reply = "ERROR\n";
        send(sock_fd, reply, strlen(reply), 0);
    }
}

static void check_socket_data(void)
{
    char buffer[512];
    ssize_t n;
    
    // 如果未连接，直接返回
    if (sock_fd < 0) {
        return;
    }
    
    // 接收数据
    n = recv(sock_fd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
    if (n > 0) {
        buffer[n] = '\0';
        process_watch_command(buffer);
    } else if (n == 0) {
        // RTL断开连接
        close(sock_fd);
        sock_fd = -1;
        if (log_file) {
            fprintf(log_file, "# RTL disconnected\n");
            fflush(log_file);
        }
        fprintf(stderr, "[Memory Watch] RTL disconnected\n");
    }
}

void memory_watch_set_enabled(bool enable)
{
    enabled = enable;
    if (enable) {
        fprintf(stderr, "[Memory Watch] Enabled\n");
    } else {
        fprintf(stderr, "[Memory Watch] Disabled\n");
    }
}

bool memory_watch_is_enabled(void)
{
    return enabled;
}

void memory_watch_check_access(CPUState *cpu, hwaddr paddr, 
                               unsigned size, bool is_write)
{
    static uint64_t total_calls = 0;
    total_calls++;
    
    if (!initialized || !watched_addresses || !enabled) {
        return;
    }
    
    if ((total_calls % 100000) == 0) {
        fprintf(stderr, "[MEMWATCH_DEBUG] check_access called %lu times\n", 
                (unsigned long)total_calls);
    }
    
    static int check_counter = 0;
    if (++check_counter >= 1000) {
        check_socket_data();
        check_counter = 0;
    }
    
    fprintf(stderr, "[MEMWATCH_DEBUG] Before mutex_lock, addr=0x%lx\n", 
            (unsigned long)paddr);
    qemu_mutex_lock(&watch_lock);
    fprintf(stderr, "[MEMWATCH_DEBUG] After mutex_lock, addr=0x%lx\n", 
            (unsigned long)paddr);
    
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
    
    fprintf(stderr, "[MEMWATCH_DEBUG] Before mutex_unlock, addr=0x%lx\n", 
            (unsigned long)paddr);
    qemu_mutex_unlock(&watch_lock);
    fprintf(stderr, "[MEMWATCH_DEBUG] After mutex_unlock, addr=0x%lx\n", 
            (unsigned long)paddr);
}

void memory_watch_init(void)
{
    fprintf(stderr, "[MEMWATCH_DEBUG] ========== memory_watch_init() ENTER ==========\n");
    
    if (initialized) {
        fprintf(stderr, "[MEMWATCH_DEBUG] Already initialized, returning\n");
        return;
    }
    
    fprintf(stderr, "[MEMWATCH_DEBUG] Checking ENABLE_MEMORY_WATCH environment variable\n");
    // 检查环境变量ENABLE_MEMORY_WATCH
    const char *env_enable = getenv("ENABLE_MEMORY_WATCH");
    if (env_enable && (strcmp(env_enable, "1") == 0 || strcmp(env_enable, "yes") == 0)) {
        enabled = true;
        fprintf(stderr, "[Memory Watch] Enabled via ENABLE_MEMORY_WATCH\n");
        fprintf(stderr, "[MEMWATCH_DEBUG] enabled = true\n");
    } else {
        enabled = false;
        fprintf(stderr, "[Memory Watch] Disabled (set ENABLE_MEMORY_WATCH=1 to enable)\n");
        fprintf(stderr, "[MEMWATCH_DEBUG] enabled = false\n");
        fprintf(stderr, "[MEMWATCH_DEBUG] Skipping initialization (disabled)\n");
        fprintf(stderr, "[MEMWATCH_DEBUG] ========== memory_watch_init() EXIT ==========\n");
        initialized = true;  // Mark as initialized to prevent re-entry
        return;  // Early return - skip all initialization
    }
    
    // Only initialize if enabled
    fprintf(stderr, "[MEMWATCH_DEBUG] Opening log file: %s\n", LOG_PATH);
    log_file = fopen(LOG_PATH, "w");
    if (!log_file) {
        fprintf(stderr, "[MEMWATCH_DEBUG] Failed to open log file\n");
        return;
    }
    fprintf(stderr, "[MEMWATCH_DEBUG] Log file opened successfully\n");
    
    fprintf(log_file, "# QEMU Memory Watch (Integrated)\n");
    fprintf(log_file, "# Format: [TIMESTAMP] CPU OP ADDR SIZE TYPE SLOT\n");
    fprintf(log_file, "# Enabled: yes\n\n");
    
    fprintf(stderr, "[MEMWATCH_DEBUG] Initializing mutex\n");
    qemu_mutex_init(&watch_lock);
    fprintf(stderr, "[MEMWATCH_DEBUG] Mutex initialized\n");
    
    fprintf(stderr, "[MEMWATCH_DEBUG] Creating hash table\n");
    watched_addresses = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             NULL, g_free);
    fprintf(stderr, "[MEMWATCH_DEBUG] Hash table created\n");
    
    // 立即尝试连接RTL socket（RTL应该已经在等待）
    fprintf(stderr, "[Memory Watch] Connecting to RTL socket...\n");
    fprintf(stderr, "[MEMWATCH_DEBUG] Calling connect_to_rtl()\n");
    sock_fd = connect_to_rtl();
    fprintf(stderr, "[MEMWATCH_DEBUG] connect_to_rtl() returned fd=%d\n", sock_fd);
    
    if (sock_fd >= 0) {
        fprintf(log_file, "# Connected to RTL socket\n\n");
        fprintf(stderr, "[Memory Watch] Connected to RTL successfully\n");
        fprintf(stderr, "[MEMWATCH_DEBUG] RTL socket connected, fd=%d\n", sock_fd);
    } else {
        fprintf(log_file, "# Warning: Not connected to RTL\n\n");
        fprintf(stderr, "[Memory Watch] Warning: Failed to connect to RTL\n");
        fprintf(stderr, "[MEMWATCH_DEBUG] RTL socket connection failed\n");
    }
    
    fflush(log_file);
    initialized = true;
    fprintf(stderr, "[MEMWATCH_DEBUG] initialized = true\n");
    fprintf(stderr, "[MEMWATCH_DEBUG] ========== memory_watch_init() EXIT ==========\n");
}

void memory_watch_cleanup(void)
{
    if (!initialized) {
        return;
    }
    
    // 如果禁用，直接返回（没有mutex需要清理）
    if (!enabled) {
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
