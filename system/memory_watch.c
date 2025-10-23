/*
 * QEMU Memory Watch - Integrated Version
 * 监测Windows对xHCI设备上下文的物理内存访问
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/thread.h"
#include "hw/core/cpu.h"
#include "sysemu/memory_watch.h"
#include "trace.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "qemu/cutils.h"
static char *socket_path = NULL;
static int sock_fd = -1;
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
    
    if (!socket_path) {
        fprintf(stderr, "[MEMWATCH_THREAD] Socket path not configured\n");
        return -1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    g_strlcpy(addr.sun_path, socket_path, sizeof(addr.sun_path));
    
    fprintf(stderr, "[MEMWATCH_THREAD] Starting connection attempts to RTL (unlimited retries)... socket path: %s\n", socket_path);
    
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


static void process_watch_command(const char *cmd)
{
    uint64_t addr;
    int size;
    char info_str[256] = {0};
    
    // 解析: "WATCH 0x<ADDR> <SIZE> [INFO]\n"
    // 先尝试解析带info的格式
    int n = sscanf(cmd, "WATCH 0x%" PRIx64 " %d %255[^\n]", &addr, &size, info_str);
    
    if (n >= 2) {  // 至少需要地址和大小
        
        qemu_mutex_lock(&watch_lock);
        
        bool success = false;
        if (!g_hash_table_contains(watched_addresses, GUINT_TO_POINTER(addr))) {
            WatchRange *range = g_new(WatchRange, 1);
            range->start = addr;
            range->end = addr + size;
            
            g_hash_table_insert(watched_addresses, GUINT_TO_POINTER(addr), range);
            
            // 使用trace事件记录
            if (n >= 3 && strlen(info_str) > 0) {
                trace_memory_watch_add_region(addr, size, info_str);
                qemu_log(": memory_watch_add_region: addr: %" PRIx64 " size: %d info: %s\n",
                         addr, size, info_str);
                fprintf(stderr, "[MEMWATCH_THREAD] Received command: WATCH 0x%016" PRIx64 " %d [%s]\n",
                        addr, size, info_str);
            } else {
                trace_memory_watch_add_region(addr, size, "");
                qemu_log(": memory_watch_add_region: addr: %" PRIx64 " size: %d\n",
                         addr, size);
                fprintf(stderr, "[MEMWATCH_THREAD] Received command: WATCH 0x%016" PRIx64 " %d\n",
                        addr, size);
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
        thread_running = false;
        return NULL;
    }
    
    fprintf(stderr, "[MEMWATCH_THREAD] Connected to RTL successfully, fd=%d\n", sock_fd);
    
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
            unsigned int cpu_index = cpu ? cpu->cpu_index : 0;
            
            // 使用trace事件记录访问
            if (is_write) {
                trace_memory_watch_access_write(cpu_index, paddr, size);
            } else {
                trace_memory_watch_access_read(cpu_index, paddr, size);
            }
            
            // 使用remote_port风格的qemu_log输出
            qemu_log(": memory_watch_access: address: %" PRIx64 "\n", paddr);
            
            // 读取并输出内存内容（使用qemu_hexdump）
            if (cpu) {
                CPUClass *cc = CPU_GET_CLASS(cpu);
                if (cc->memory_rw_debug) {
                    uint8_t buf[32] = {0};  // 最多读取32字节
                    int read_size = size > 32 ? 32 : size;
                    if (cc->memory_rw_debug(cpu, paddr, buf, read_size, false) == 0) {
                        qemu_hexdump(stderr, is_write ? ": write: " : ": read: ",
                                     (const char *)buf, read_size);
                    }
                }
            }
            
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
    
    fprintf(stderr, "[MEMWATCH_DEBUG] Checking MEMORY_WATCH_PATH environment variable\n");
    // 从环境变量获取socket路径
    const char *env_path = getenv("MEMORY_WATCH_PATH");
    if (!env_path || strlen(env_path) == 0) {
        enabled = false;
        fprintf(stderr, "[Memory Watch] Disabled (MEMORY_WATCH_PATH not set or empty)\n");
        fprintf(stderr, "[MEMWATCH_DEBUG] Skipping initialization (disabled)\n");
        fprintf(stderr, "[MEMWATCH_DEBUG] ========== memory_watch_init() EXIT ==========\n");
        initialized = true;  // Mark as initialized to prevent re-entry
        return;  // Early return - skip all initialization
    }
    
    // 保存socket路径
    socket_path = g_strdup(env_path);
    enabled = true;
    fprintf(stderr, "[Memory Watch] Enabled with socket path: %s\n", socket_path);
    fprintf(stderr, "[MEMWATCH_DEBUG] enabled = true\n");
    
    // Only initialize if enabled
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
    
    // 使用trace事件记录初始化
    trace_memory_watch_init();
    qemu_log(": memory_watch_init: enabled with socket path %s\n", socket_path);
    
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
    
    // 打印统计信息到stderr
    fprintf(stderr, "[Memory Watch] Statistics:\n");
    fprintf(stderr, "[Memory Watch]   Total accesses: %" PRIu64 "\n", access_count);
    if (watched_addresses) {
        fprintf(stderr, "[Memory Watch]   Watched addresses: %u\n",
                g_hash_table_size(watched_addresses));
    }
    
    if (watched_addresses) {
        g_hash_table_destroy(watched_addresses);
        watched_addresses = NULL;
    }
    
    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
    
    if (socket_path) {
        g_free(socket_path);
        socket_path = NULL;
    }
    
    qemu_mutex_unlock(&watch_lock);
    initialized = false;
}
