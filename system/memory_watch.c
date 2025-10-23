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
#include <errno.h>

#define SOCKET_PATH "/tmp/xhci_context_monitor.sock"
#define LOG_PATH "/tmp/qemu_memory_watch.log"

static int sock_fd = -1;
static FILE *log_file = NULL;
static GHashTable *watched_addresses = NULL;
static QemuMutex watch_lock;
static uint64_t access_count = 0;
static bool initialized = false;
static volatile bool enabled = false;  // volatile for lock-free read
static QemuThread rtl_thread;
static volatile bool thread_running = false;
static volatile bool thread_should_exit = false;

typedef struct {
    uint64_t start;
    uint64_t end;
} WatchRange;

static int connect_to_rtl(void)
{
    struct sockaddr_un addr;
    int fd;
    int retry_count = 0;
    const int retry_delay_ms = 200;  // 每次重试间隔200ms
    const int log_interval = 10;     // 每10次尝试打印一次日志
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    g_strlcpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path));
    
    fprintf(stderr, "[MEMWATCH_THREAD] Starting connection attempts to RTL (unlimited retries)... socket path: %s\n", SOCKET_PATH);
    
    // 无限重试连接，直到成功或线程被要求退出
    while (!thread_should_exit) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            fprintf(stderr, "[MEMWATCH_THREAD] Failed to create socket: %s\n", strerror(errno));
            g_usleep(retry_delay_ms * 1000);
            continue;
        }
        
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            // 连接成功，保持阻塞模式用于后台线程
            fprintf(stderr, "[MEMWATCH_THREAD] Connected to RTL successfully after %d attempts\n", retry_count + 1);
            return fd;
        }
        
        // 定期打印日志，避免刷屏
        if (retry_count == 0 || (retry_count + 1) % log_interval == 0) {
            fprintf(stderr, "[MEMWATCH_THREAD] Connect attempt %d failed: %s (will keep retrying...)\n", 
                    retry_count + 1, strerror(errno));
        }
        close(fd);
        
        retry_count++;
        g_usleep(retry_delay_ms * 1000);  // 转换为微秒
    }
    
    fprintf(stderr, "[MEMWATCH_THREAD] Connection attempts cancelled after %d tries\n", retry_count);
    return -1;
}

static void log_access(const char *op, uint64_t addr, unsigned size, unsigned int cpu)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    if (log_file) {
        fprintf(log_file, "[%ld.%06ld] CPU%u %s 0x%016" PRIx64 " size=%u\n",
                (long)tv.tv_sec, (long)tv.tv_usec, cpu, op, addr, size);
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

// 后台线程函数：处理RTL连接和命令
static void *rtl_thread_func(void *arg)
{
    char buffer[512];
    ssize_t n;
    
    fprintf(stderr, "[MEMWATCH_THREAD] Background thread started\n");
    
    // 尝试连接到RTL
    sock_fd = connect_to_rtl();
    
    if (sock_fd < 0) {
        fprintf(stderr, "[MEMWATCH_THREAD] Failed to connect to RTL, thread exiting\n");
        qemu_mutex_lock(&watch_lock);
        if (log_file) {
            fprintf(log_file, "# Warning: Failed to connect to RTL\n\n");
            fflush(log_file);
        }
        qemu_mutex_unlock(&watch_lock);
        thread_running = false;
        return NULL;
    }
    
    fprintf(stderr, "[MEMWATCH_THREAD] Connected to RTL successfully, fd=%d\n", sock_fd);
    qemu_mutex_lock(&watch_lock);
    if (log_file) {
        fprintf(log_file, "# Connected to RTL socket\n\n");
        fflush(log_file);
    }
    qemu_mutex_unlock(&watch_lock);
    
    // 主循环：接收和处理命令
    while (!thread_should_exit) {
        // 阻塞接收（带超时）
        struct timeval tv;
        fd_set readfds;
        
        FD_ZERO(&readfds);
        FD_SET(sock_fd, &readfds);
        tv.tv_sec = 1;  // 1秒超时
        tv.tv_usec = 0;
        
        int ret = select(sock_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (ret < 0) {
            if (errno == EINTR) {
                continue;  // 被信号中断，继续
            }
            fprintf(stderr, "[MEMWATCH_THREAD] select() error: %s\n", strerror(errno));
            break;
        }
        
        if (ret == 0) {
            // 超时，继续循环检查thread_should_exit
            continue;
        }
        
        // 有数据可读
        n = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            fprintf(stderr, "[MEMWATCH_THREAD] Received command: %s", buffer);
            process_watch_command(buffer);
        } else if (n == 0) {
            // RTL断开连接
            fprintf(stderr, "[MEMWATCH_THREAD] RTL disconnected\n");
            qemu_mutex_lock(&watch_lock);
            if (log_file) {
                fprintf(log_file, "# RTL disconnected\n");
                fflush(log_file);
            }
            qemu_mutex_unlock(&watch_lock);
            break;
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "[MEMWATCH_THREAD] recv() error: %s\n", strerror(errno));
                break;
            }
        }
    }
    
    // 清理
    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
    
    fprintf(stderr, "[MEMWATCH_THREAD] Background thread exiting\n");
    thread_running = false;
    return NULL;
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
    if (!initialized || !watched_addresses || !enabled) {
        return;
    }
    
    // 快速路径：无锁检查（仅在有监控地址时才加锁）
    if (g_hash_table_size(watched_addresses) == 0) {
        return;
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
            
            log_access(op, paddr, size, cpu_index);
            
            access_count++;
            break;
        }
    }
    
    qemu_mutex_unlock(&watch_lock);
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
    fprintf(log_file, "# Format: [TIMESTAMP] CPU OP ADDR SIZE\n");
    fprintf(log_file, "# Enabled: yes\n\n");
    
    fprintf(stderr, "[MEMWATCH_DEBUG] Initializing mutex\n");
    qemu_mutex_init(&watch_lock);
    fprintf(stderr, "[MEMWATCH_DEBUG] Mutex initialized\n");
    
    fprintf(stderr, "[MEMWATCH_DEBUG] Creating hash table\n");
    watched_addresses = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             NULL, g_free);
    fprintf(stderr, "[MEMWATCH_DEBUG] Hash table created\n");
    
    // 启动后台线程处理RTL连接和命令
    fprintf(stderr, "[Memory Watch] Starting background thread for RTL connection...\n");
    thread_should_exit = false;
    thread_running = true;
    qemu_thread_create(&rtl_thread, "memwatch-rtl", rtl_thread_func, NULL, 
                       QEMU_THREAD_DETACHED);
    fprintf(stderr, "[Memory Watch] Background thread started\n");
    
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
    
    // 停止后台线程
    if (thread_running) {
        fprintf(stderr, "[Memory Watch] Stopping background thread...\n");
        thread_should_exit = true;
        
        // 等待线程退出（最多2秒）
        int wait_count = 0;
        while (thread_running && wait_count < 20) {
            g_usleep(100000);  // 100ms
            wait_count++;
        }
        
        if (thread_running) {
            fprintf(stderr, "[Memory Watch] Warning: Background thread did not exit cleanly\n");
        } else {
            fprintf(stderr, "[Memory Watch] Background thread stopped\n");
        }
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
