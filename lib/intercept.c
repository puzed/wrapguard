#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <errno.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#ifdef __APPLE__
#include <crt_externs.h>
#endif

// Function pointers for original functions
static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*real_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*real_getpeername)(int sockfd, struct sockaddr *addr, socklen_t *addrlen) = NULL;
static int (*real_close)(int fd) = NULL;
#ifdef __APPLE__
static int (*real_connectx)(int sockfd, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid) = NULL;
#endif

// Global variables for configuration
static char *ipc_path = NULL;
static int socks_port = 0;
static int initialized = 0;
static int debug_mode_cached = 0;
static int debug_ipc_cached = 0;
static int block_udp_443_cached = 0;
static int macos_no_inherit_cached = 0;
static int passthrough_mode_cached = 0;
static int expect_ready_cached = 0;
static __thread int internal_connect_guard = 0;

static int wrapguard_connect_impl(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int wrapguard_bind_impl(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
#ifdef __APPLE__
static int wrapguard_connectx_impl(int sockfd, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid);
#endif
static ssize_t wrapguard_sendto_impl(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
static ssize_t wrapguard_sendmsg_impl(int sockfd, const struct msghdr *msg, int flags);
static int raw_connect_call(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int raw_bind_call(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int raw_close_call(int fd);
static int wait_for_socket(int sockfd, int for_write, int timeout_seconds);
static int recv_exact_with_timeout(int sockfd, unsigned char *buf, size_t len, int timeout_seconds);
static int send_all_with_timeout(int sockfd, const unsigned char *buf, size_t len, int timeout_seconds);
static const char *family_name(sa_family_t family);
static const char *socket_type_name(int sock_type);
#ifndef __APPLE__
static int call_real_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
#endif
static int call_real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int call_real_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int call_real_close(int fd);
#ifdef __APPLE__
static int call_real_connectx(int sockfd, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid);
#endif
static int is_loopback_connect(const struct sockaddr *addr);
static int is_nonblocking_socket(int sockfd);
static int block_udp_443_enabled(void);
static int should_block_udp_target(const struct sockaddr *addr);
static int should_block_udp_send_target(int sockfd, const struct sockaddr *addr, socklen_t addrlen, char *buf, size_t buf_len);
static int sockaddr_port(const struct sockaddr *addr);
static void format_sockaddr(const struct sockaddr *addr, char *buf, size_t buf_len);
static void remember_virtual_peer(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
#ifndef __APPLE__
static int lookup_virtual_peer(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
#endif
static void forget_virtual_peer(int sockfd);
static void send_ipc_message(const char *type, int fd, int port, const char *addr);
static int should_passthrough_current_process(void);
static int expect_ready_enabled(void);

#ifdef __APPLE__
static const char *process_basename(const char *path) {
    if (path == NULL) {
        return "";
    }
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

static int str_equals(const char *value, const char *expected) {
    return value != NULL && expected != NULL && strcmp(value, expected) == 0;
}

static int should_passthrough_mozilla_process(char *const *argv) {
    if (argv == NULL || argv[0] == NULL) {
        return 0;
    }

    const char *base = process_basename(argv[0]);
    if (str_equals(base, "plugin-container")) {
        size_t argc = 0;
        while (argv[argc] != NULL) {
            argc++;
        }
        if (argc > 1 && str_equals(argv[argc - 1], "socket")) {
            return 0;
        }
        return 1;
    }

    if (strstr(base, "GPU Helper") != NULL || str_equals(base, "gpu-helper")) {
        return 1;
    }

    return 0;
}
#endif


struct virtual_peer_entry {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct virtual_peer_entry *next;
};

static pthread_mutex_t virtual_peer_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct virtual_peer_entry *virtual_peers = NULL;

#ifdef __APPLE__
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_replacee \
    };
#endif

static const char *debug_prefix(void) {
#ifdef __APPLE__
    return "WrapGuard DYLD: ";
#else
    return "WrapGuard LD_PRELOAD: ";
#endif
}

static int debug_enabled(void) {
    if (initialized) {
        return debug_mode_cached && !passthrough_mode_cached;
    }
    char *debug_mode = getenv("WRAPGUARD_DEBUG");
    return debug_mode != NULL && strcmp(debug_mode, "1") == 0;
}

static int debug_ipc_enabled(void) {
#ifdef __APPLE__
    if (initialized) {
        return debug_ipc_cached;
    }
    char *value = getenv("WRAPGUARD_DEBUG_IPC");
    return value != NULL && strcmp(value, "1") == 0;
#else
    return 0;
#endif
}

static void write_stderr_line(const char *prefix, const char *message) {
    char buffer[768];
    int written = snprintf(buffer, sizeof(buffer), "%s%s\n", prefix ? prefix : "", message ? message : "");
    if (written <= 0) {
        return;
    }

    size_t len = (size_t)written;
    if (len >= sizeof(buffer)) {
        len = sizeof(buffer) - 1;
    }

    size_t offset = 0;
    while (offset < len) {
        ssize_t chunk = write(STDERR_FILENO, buffer + offset, len - offset);
        if (chunk < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        offset += (size_t)chunk;
    }
}

static void log_debugf(const char *fmt, ...) {
    if (!debug_enabled()) {
        return;
    }
    int saved_errno = errno;

    char message[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);

#ifdef __APPLE__
    if (debug_ipc_enabled() && ipc_path != NULL) {
        send_ipc_message("DEBUG", -1, 0, message);
        errno = saved_errno;
        return;
    }
    write_stderr_line(debug_prefix(), message);
#else
    fprintf(stderr, "%s%s\n", debug_prefix(), message);
#endif
    errno = saved_errno;
}

static void log_errorf(const char *fmt, ...) {
    int saved_errno = errno;

    char message[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);

#ifdef __APPLE__
    if (debug_ipc_enabled() && ipc_path != NULL) {
        send_ipc_message("ERROR", -1, 0, message);
        errno = saved_errno;
        return;
    }
    write_stderr_line(debug_prefix(), message);
#else
    fprintf(stderr, "%s%s\n", debug_prefix(), message);
#endif
    errno = saved_errno;
}

static int block_udp_443_enabled(void) {
    if (initialized) {
        return block_udp_443_cached;
    }
    char *value = getenv("WRAPGUARD_BLOCK_UDP_443");
    return value != NULL && strcmp(value, "1") == 0;
}

static int macos_no_inherit_enabled(void) {
#ifdef __APPLE__
    if (initialized) {
        return macos_no_inherit_cached;
    }
    char *value = getenv("WRAPGUARD_MACOS_NO_INHERIT");
    return value != NULL && strcmp(value, "1") == 0;
#else
    return 0;
#endif
}

static int expect_ready_enabled(void) {
    if (initialized) {
        return expect_ready_cached;
    }
    char *value = getenv("WRAPGUARD_EXPECT_READY");
    return value != NULL && strcmp(value, "1") == 0;
}

static const char *family_name(sa_family_t family) {
    switch (family) {
        case AF_UNIX:
            return "AF_UNIX";
        case AF_INET:
            return "AF_INET";
        case AF_INET6:
            return "AF_INET6";
        default:
            return "AF_UNKNOWN";
    }
}

static const char *socket_type_name(int sock_type) {
    switch (sock_type) {
        case SOCK_STREAM:
            return "SOCK_STREAM";
        case SOCK_DGRAM:
            return "SOCK_DGRAM";
#ifdef SOCK_SEQPACKET
        case SOCK_SEQPACKET:
            return "SOCK_SEQPACKET";
#endif
        default:
            return "SOCK_OTHER";
    }
}

#ifndef __APPLE__
static int call_real_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (real_connect == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_connect(sockfd, addr, addrlen);
}
#endif

static int call_real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#ifdef __APPLE__
    return raw_bind_call(sockfd, addr, addrlen);
#else
    if (real_bind == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_bind(sockfd, addr, addrlen);
#endif
}

static int call_real_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (real_getpeername == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_getpeername(sockfd, addr, addrlen);
}

static int call_real_close(int fd) {
#ifdef __APPLE__
    return raw_close_call(fd);
#else
    if (real_close == NULL) {
        return raw_close_call(fd);
    }
    return real_close(fd);
#endif
}

#ifdef __APPLE__
static int call_real_connectx(int sockfd, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid) {
    if (real_connectx == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_connectx(sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);
}
#endif

#ifdef __APPLE__
static int raw_connectx_call(int sockfd, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return (int)syscall(SYS_connectx, sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);
#pragma clang diagnostic pop
}
#endif

static int raw_connect_call(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    return (int)syscall(SYS_connect, sockfd, addr, addrlen);
#ifdef __APPLE__
#pragma clang diagnostic pop
#endif
}

static int raw_bind_call(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    return (int)syscall(SYS_bind, sockfd, addr, addrlen);
#ifdef __APPLE__
#pragma clang diagnostic pop
#endif
}

static int raw_close_call(int fd) {
#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    return (int)syscall(SYS_close, fd);
#ifdef __APPLE__
#pragma clang diagnostic pop
#endif
}

static int wait_for_socket(int sockfd, int for_write, int timeout_seconds) {
    for (;;) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);

        struct timeval timeout;
        timeout.tv_sec = timeout_seconds;
        timeout.tv_usec = 0;

        int result = select(sockfd + 1, for_write ? NULL : &fds, for_write ? &fds : NULL, NULL, &timeout);
        if (result >= 0) {
            return result;
        }
        if (errno != EINTR) {
            return -1;
        }
    }
}

static int recv_exact_with_timeout(int sockfd, unsigned char *buf, size_t len, int timeout_seconds) {
    size_t offset = 0;

    while (offset < len) {
        int select_result = wait_for_socket(sockfd, 0, timeout_seconds);
        if (select_result <= 0) {
            return -1;
        }

        ssize_t chunk = recv(sockfd, buf + offset, len - offset, 0);
        if (chunk <= 0) {
            if (chunk < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            return -1;
        }

        offset += (size_t)chunk;
    }

    return 0;
}

static int send_all_with_timeout(int sockfd, const unsigned char *buf, size_t len, int timeout_seconds) {
    size_t offset = 0;

    while (offset < len) {
        int select_result = wait_for_socket(sockfd, 1, timeout_seconds);
        if (select_result <= 0) {
            return -1;
        }

        ssize_t chunk = send(sockfd, buf + offset, len - offset, 0);
        if (chunk < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            return -1;
        }

        offset += (size_t)chunk;
    }

    return 0;
}

static int is_loopback_connect(const struct sockaddr *addr) {
    if (addr == NULL) {
        return 0;
    }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
        uint32_t ip = ntohl(in_addr->sin_addr.s_addr);
        return (ip & 0xFF000000) == 0x7F000000;
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6_addr = (const struct sockaddr_in6 *)addr;
        return IN6_IS_ADDR_LOOPBACK(&in6_addr->sin6_addr);
    }

    return 0;
}

static int is_nonblocking_socket(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL);
    if (flags < 0) {
        return 0;
    }
    return (flags & O_NONBLOCK) != 0;
}

static int sockaddr_port(const struct sockaddr *addr) {
    if (addr == NULL) {
        return 0;
    }
    if (addr->sa_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)addr)->sin_port);
    }
    if (addr->sa_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
    }
    return 0;
}

static void format_sockaddr(const struct sockaddr *addr, char *buf, size_t buf_len) {
    if (buf_len == 0) {
        return;
    }
    if (addr == NULL) {
        snprintf(buf, buf_len, "NULL");
        return;
    }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *in_addr = (const struct sockaddr_in *)addr;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in_addr->sin_addr, ip_str, sizeof(ip_str));
        snprintf(buf, buf_len, "%s:%d", ip_str, ntohs(in_addr->sin_port));
        return;
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6_addr = (const struct sockaddr_in6 *)addr;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &in6_addr->sin6_addr, ip_str, sizeof(ip_str));
        snprintf(buf, buf_len, "[%s]:%d", ip_str, ntohs(in6_addr->sin6_port));
        return;
    }

    snprintf(buf, buf_len, "%s(%d)", family_name(addr->sa_family), addr->sa_family);
}

static void remember_virtual_peer(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr == NULL || addrlen == 0) {
        return;
    }

    if ((size_t)addrlen > sizeof(struct sockaddr_storage)) {
        addrlen = sizeof(struct sockaddr_storage);
    }

    pthread_mutex_lock(&virtual_peer_mutex);

    struct virtual_peer_entry *entry = virtual_peers;
    while (entry != NULL) {
        if (entry->fd == sockfd) {
            memset(&entry->addr, 0, sizeof(entry->addr));
            memcpy(&entry->addr, addr, (size_t)addrlen);
            entry->addrlen = addrlen;
            pthread_mutex_unlock(&virtual_peer_mutex);
            return;
        }
        entry = entry->next;
    }

    entry = (struct virtual_peer_entry *)calloc(1, sizeof(*entry));
    if (entry != NULL) {
        entry->fd = sockfd;
        memcpy(&entry->addr, addr, (size_t)addrlen);
        entry->addrlen = addrlen;
        entry->next = virtual_peers;
        virtual_peers = entry;
    }

    pthread_mutex_unlock(&virtual_peer_mutex);
}

#ifndef __APPLE__
static int lookup_virtual_peer(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int found = 0;

    if (addr == NULL || addrlen == NULL) {
        return 0;
    }

    pthread_mutex_lock(&virtual_peer_mutex);

    struct virtual_peer_entry *entry = virtual_peers;
    while (entry != NULL) {
        if (entry->fd == sockfd) {
            socklen_t copy_len = entry->addrlen;
            if (*addrlen < copy_len) {
                copy_len = *addrlen;
            }
            memcpy(addr, &entry->addr, (size_t)copy_len);
            *addrlen = entry->addrlen;
            found = 1;
            break;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&virtual_peer_mutex);
    return found;
}
#endif

static void forget_virtual_peer(int sockfd) {
    pthread_mutex_lock(&virtual_peer_mutex);

    struct virtual_peer_entry *entry = virtual_peers;
    struct virtual_peer_entry *prev = NULL;
    while (entry != NULL) {
        if (entry->fd == sockfd) {
            if (prev == NULL) {
                virtual_peers = entry->next;
            } else {
                prev->next = entry->next;
            }
            free(entry);
            break;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&virtual_peer_mutex);
}

static int should_block_udp_target(const struct sockaddr *addr) {
    if (!block_udp_443_enabled()) {
        return 0;
    }
    if (addr == NULL) {
        return 0;
    }
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return 0;
    }
    if (is_loopback_connect(addr)) {
        return 0;
    }
    return sockaddr_port(addr) == 443;
}

static int should_block_udp_send_target(int sockfd, const struct sockaddr *addr, socklen_t addrlen, char *buf, size_t buf_len) {
    struct sockaddr_storage target_storage;
    const struct sockaddr *target = addr;
    socklen_t target_len = addrlen;

    if (target == NULL || target_len < (socklen_t)sizeof(sa_family_t)) {
        memset(&target_storage, 0, sizeof(target_storage));
        target_len = sizeof(target_storage);
        if (call_real_getpeername(sockfd, (struct sockaddr *)&target_storage, &target_len) != 0) {
            return 0;
        }
        target = (const struct sockaddr *)&target_storage;
    }

    if (!should_block_udp_target(target)) {
        return 0;
    }

    if (buf != NULL && buf_len > 0) {
        format_sockaddr(target, buf, buf_len);
    }

    return 1;
}

// Initialize the library
static void init_library(void) {
    if (initialized) return;
    debug_mode_cached = debug_enabled();
    debug_ipc_cached = debug_ipc_enabled();
    block_udp_443_cached = block_udp_443_enabled();
    macos_no_inherit_cached = macos_no_inherit_enabled();
    passthrough_mode_cached = should_passthrough_current_process();
    expect_ready_cached = expect_ready_enabled();
    initialized = 1;

#ifdef __APPLE__
    if (expect_ready_cached) {
        unsetenv("WRAPGUARD_EXPECT_READY");
    }

    if (passthrough_mode_cached) {
        char *ipc_path_env = getenv("WRAPGUARD_IPC_PATH");
        if (ipc_path_env != NULL) {
            ipc_path = strdup(ipc_path_env);
        }
        char *socks_port_str = getenv("WRAPGUARD_SOCKS_PORT");
        if (socks_port_str != NULL) {
            socks_port = atoi(socks_port_str);
        }

        if (expect_ready_cached && ipc_path != NULL && socks_port != 0) {
            send_ipc_message("READY", -1, socks_port, NULL);
        }
        return;
    }
#endif
    
    // Load original functions
#ifdef __APPLE__
    dlerror();
    real_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    const char *connect_err = dlerror();
    dlerror();
    real_bind = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "bind");
    const char *bind_err = dlerror();
    dlerror();
    real_getpeername = (int (*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "getpeername");
    const char *getpeername_err = dlerror();
    dlerror();
    real_connectx = (int (*)(int, const sa_endpoints_t *, sae_associd_t, unsigned int, const struct iovec *, unsigned int, size_t *, sae_connid_t *))dlsym(RTLD_NEXT, "connectx");
    const char *connectx_err = dlerror();
    const char *close_err = NULL;
#else
    dlerror();
    real_connect = dlsym(RTLD_NEXT, "connect");
    const char *connect_err = dlerror();
    dlerror();
    real_bind = dlsym(RTLD_NEXT, "bind");
    const char *bind_err = dlerror();
    dlerror();
    real_getpeername = dlsym(RTLD_NEXT, "getpeername");
    const char *getpeername_err = dlerror();
    dlerror();
    real_close = dlsym(RTLD_NEXT, "close");
    const char *close_err = dlerror();
    const char *connectx_err = "unsupported";
#endif

    if (real_connect == NULL || real_bind == NULL || real_getpeername == NULL
#ifndef __APPLE__
        || real_close == NULL
#else
        || real_connectx == NULL
#endif
    ) {
        log_errorf("Failed to resolve original socket symbols (connect=%s bind=%s getpeername=%s connectx=%s close=%s)",
                   connect_err ? connect_err : "unknown",
                   bind_err ? bind_err : "unknown",
                   getpeername_err ? getpeername_err : "unknown",
                   connectx_err ? connectx_err : "unknown",
                   close_err ? close_err : "syscall");
        return;
    }
    
    // Get configuration from environment
    char *ipc_path_env = getenv("WRAPGUARD_IPC_PATH");
    if (ipc_path_env != NULL) {
        ipc_path = strdup(ipc_path_env);
    }
    char *socks_port_str = getenv("WRAPGUARD_SOCKS_PORT");
    if (socks_port_str) {
        socks_port = atoi(socks_port_str);
    }

#ifdef __APPLE__
    if (macos_no_inherit_cached) {
        unsetenv("DYLD_INSERT_LIBRARIES");
        unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
        unsetenv("WRAPGUARD_IPC_PATH");
        unsetenv("WRAPGUARD_SOCKS_PORT");
        unsetenv("WRAPGUARD_DEBUG");
        unsetenv("WRAPGUARD_DEBUG_IPC");
        unsetenv("WRAPGUARD_BLOCK_UDP_443");
        unsetenv("WRAPGUARD_MACOS_NO_INHERIT");
    }
#endif
    
    if (debug_enabled()) {
        log_debugf("Initialized");
        log_debugf("IPC path: %s", ipc_path ? ipc_path : "NULL");
        log_debugf("SOCKS port: %d", socks_port);
        log_debugf("Resolved real symbols connect=%p bind=%p getpeername=%p connectx=%p close=%p", (void *)real_connect, (void *)real_bind, (void *)real_getpeername, (void *)real_connectx, (void *)real_close);
        if (block_udp_443_enabled()) {
            log_debugf("Likely QUIC UDP/443 suppression is enabled");
        }
    }
    
    if (!ipc_path || socks_port == 0) {
        log_errorf("WrapGuard: Missing environment variables");
        return;
    }

    if (expect_ready_cached) {
        send_ipc_message("READY", -1, socks_port, NULL);
        if (debug_enabled()) {
            log_debugf("Interceptor loaded and announced readiness");
        }
    }
}

static int should_passthrough_current_process(void) {
#ifdef __APPLE__
    char ***argv_ptr = _NSGetArgv();
    if (argv_ptr == NULL) {
        return 0;
    }
    return should_passthrough_mozilla_process(*argv_ptr);
#else
    return 0;
#endif
}

__attribute__((constructor))
static void wrapguard_constructor(void) {
    init_library();
}

// Check if an address should be intercepted
static int should_intercept_connect(const struct sockaddr *addr) {
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return 0; // Only intercept IP connections
    }

    if (is_loopback_connect(addr)) {
        return 0;
    }

    return 1;
}

// Send IPC message
static void send_ipc_message(const char *type, int fd, int port, const char *addr) {
    int saved_errno = errno;
    if (!ipc_path) return;
    if (internal_connect_guard > 0) {
        errno = saved_errno;
        return;
    }

    internal_connect_guard++;
    
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        internal_connect_guard--;
        return;
    }
    
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, ipc_path, sizeof(sun.sun_path) - 1);
    
    int ipc_connect_result = raw_connect_call(sock, (struct sockaddr *)&sun, sizeof(sun));
    if (ipc_connect_result == 0) {
        char message[512];
        snprintf(message, sizeof(message),
                "{\"type\":\"%s\",\"fd\":%d,\"port\":%d,\"addr\":\"%s\",\"pid\":%d}\n",
                type, fd, port, addr ? addr : "", (int)getpid());

        size_t message_len = strlen(message);
        size_t offset = 0;
        while (offset < message_len) {
            ssize_t written = write(sock, message + offset, message_len - offset);
            if (written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            offset += (size_t)written;
        }
    }
    
    raw_close_call(sock);
    internal_connect_guard--;
    errno = saved_errno;
}

#ifdef __APPLE__
static ssize_t raw_sendto_call(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return (ssize_t)syscall(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
#pragma clang diagnostic pop
}

static ssize_t raw_sendmsg_call(int sockfd, const struct msghdr *msg, int flags) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return (ssize_t)syscall(SYS_sendmsg, sockfd, msg, flags);
#pragma clang diagnostic pop
}

static ssize_t wrapguard_sendto_impl(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    init_library();
    if (passthrough_mode_cached) {
        return raw_sendto_call(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    int sock_type = 0;
    socklen_t sock_type_len = sizeof(sock_type);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &sock_type_len) != 0 || sock_type != SOCK_DGRAM) {
        return raw_sendto_call(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    char addr_str[INET6_ADDRSTRLEN + 32];
    if (should_block_udp_send_target(sockfd, dest_addr, addrlen, addr_str, sizeof(addr_str))) {
        log_debugf("Blocking likely QUIC UDP sendto() to %s", addr_str);
        errno = EHOSTUNREACH;
        return -1;
    }

    return raw_sendto_call(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t wrapguard_sendmsg_impl(int sockfd, const struct msghdr *msg, int flags) {
    init_library();
    if (passthrough_mode_cached) {
        return raw_sendmsg_call(sockfd, msg, flags);
    }

    if (msg == NULL) {
        return raw_sendmsg_call(sockfd, msg, flags);
    }

    int sock_type = 0;
    socklen_t sock_type_len = sizeof(sock_type);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &sock_type_len) != 0 || sock_type != SOCK_DGRAM) {
        return raw_sendmsg_call(sockfd, msg, flags);
    }

    char addr_str[INET6_ADDRSTRLEN + 32];
    if (should_block_udp_send_target(sockfd, (const struct sockaddr *)msg->msg_name, msg->msg_namelen, addr_str, sizeof(addr_str))) {
        log_debugf("Blocking likely QUIC UDP sendmsg() to %s", addr_str);
        errno = EHOSTUNREACH;
        return -1;
    }

    return raw_sendmsg_call(sockfd, msg, flags);
}
#endif

// SOCKS5 connection helper
static int socks5_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)addrlen;
    int was_nonblocking = is_nonblocking_socket(sockfd);

    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    struct sockaddr_in socks_addr;
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socks_addr.sin_port = htons(socks_port);
    
    if (debug_enabled()) {
        log_debugf("Connecting to SOCKS5 proxy at 127.0.0.1:%d", socks_port);
    }
    int connect_result = raw_connect_call(sockfd, (struct sockaddr *)&socks_addr, sizeof(socks_addr));
    if (connect_result != 0 && errno != EINPROGRESS) {
        forget_virtual_peer(sockfd);
        log_errorf("Failed to connect to SOCKS5 proxy: %s", strerror(errno));
        return -1;
    }
    
    if (connect_result != 0 && errno == EINPROGRESS) {
        if (debug_enabled()) {
            log_debugf("Non-blocking connect in progress, waiting...");
        }
        int select_result = wait_for_socket(sockfd, 1, 5);
        if (select_result <= 0) {
            forget_virtual_peer(sockfd);
            log_errorf("Timeout waiting for SOCKS5 connection");
            return -1;
        }
        
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) != 0) {
            forget_virtual_peer(sockfd);
            log_errorf("SOCKS5 connection failed while reading SO_ERROR: %s", strerror(errno));
            return -1;
        }
        if (so_error != 0) {
            forget_virtual_peer(sockfd);
            log_errorf("SOCKS5 connection failed: %s", strerror(so_error));
            errno = so_error;
            return -1;
        }
    }
    
    if (debug_enabled()) {
        log_debugf("Connected to SOCKS5 proxy, starting handshake");
    }
    
    unsigned char handshake[] = {0x05, 0x01, 0x00};
    if (debug_enabled()) {
        log_debugf("Sending SOCKS5 handshake");
    }
    if (send_all_with_timeout(sockfd, handshake, sizeof(handshake), 5) != 0) {
        forget_virtual_peer(sockfd);
        log_errorf("Failed to send SOCKS5 handshake: %s", strerror(errno));
        return -1;
    }
    
    unsigned char response[2];
    if (debug_enabled()) {
        log_debugf("Waiting for SOCKS5 handshake response");
    }

    if (recv_exact_with_timeout(sockfd, response, sizeof(response), 5) != 0) {
        forget_virtual_peer(sockfd);
        log_errorf("Timeout waiting for SOCKS5 handshake response");
        return -1;
    }
    if (response[0] != 0x05 || response[1] != 0x00) {
        forget_virtual_peer(sockfd);
        log_errorf("Invalid SOCKS5 handshake response: %02x %02x", response[0], response[1]);
        return -1;
    }
    if (debug_enabled()) {
        log_debugf("SOCKS5 handshake successful");
    }
    
    unsigned char connect_req[22];
    size_t connect_req_len = 0;
    connect_req[connect_req_len++] = 0x05;
    connect_req[connect_req_len++] = 0x01;
    connect_req[connect_req_len++] = 0x00;

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *target = (const struct sockaddr_in *)addr;
        connect_req[connect_req_len++] = 0x01;
        memcpy(&connect_req[connect_req_len], &target->sin_addr, 4);
        connect_req_len += 4;
        memcpy(&connect_req[connect_req_len], &target->sin_port, 2);
        connect_req_len += 2;
    } else {
        const struct sockaddr_in6 *target6 = (const struct sockaddr_in6 *)addr;
        connect_req[connect_req_len++] = 0x04;
        memcpy(&connect_req[connect_req_len], &target6->sin6_addr, 16);
        connect_req_len += 16;
        memcpy(&connect_req[connect_req_len], &target6->sin6_port, 2);
        connect_req_len += 2;
    }

    if (send_all_with_timeout(sockfd, connect_req, connect_req_len, 15) != 0) {
        forget_virtual_peer(sockfd);
        log_errorf("Failed to send SOCKS5 connect request: %s", strerror(errno));
        return -1;
    }

    unsigned char connect_resp_header[4];
    if (recv_exact_with_timeout(sockfd, connect_resp_header, sizeof(connect_resp_header), 15) != 0) {
        forget_virtual_peer(sockfd);
        log_errorf("Timeout waiting for SOCKS5 connect response");
        return -1;
    }

    if (connect_resp_header[0] != 0x05 || connect_resp_header[1] != 0x00) {
        forget_virtual_peer(sockfd);
        log_errorf("SOCKS5 connect failed: version=%02x status=%02x", connect_resp_header[0], connect_resp_header[1]);
        errno = ECONNREFUSED;
        return -1;
    }

    size_t addr_bytes = 0;
    switch (connect_resp_header[3]) {
        case 0x01:
            addr_bytes = 4 + 2;
            break;
        case 0x03: {
            unsigned char domain_len = 0;
            if (recv_exact_with_timeout(sockfd, &domain_len, 1, 15) != 0) {
                forget_virtual_peer(sockfd);
                log_errorf("Timed out reading SOCKS5 domain length");
                errno = ECONNREFUSED;
                return -1;
            }
            addr_bytes = (size_t)domain_len + 2;
            break;
        }
        case 0x04:
            addr_bytes = 16 + 2;
            break;
        default:
            forget_virtual_peer(sockfd);
            log_errorf("SOCKS5 connect failed: unsupported atyp=%02x", connect_resp_header[3]);
            errno = ECONNREFUSED;
            return -1;
    }

    if (addr_bytes > 0) {
        unsigned char addr_buf[258];
        if (recv_exact_with_timeout(sockfd, addr_buf, addr_bytes, 15) != 0) {
            forget_virtual_peer(sockfd);
            log_errorf("Timed out reading SOCKS5 connect address payload");
            errno = ECONNREFUSED;
            return -1;
        }
    }

    if (debug_enabled()) {
        log_debugf("SOCKS5 connect successful");
    }

    remember_virtual_peer(sockfd, addr, addrlen);

    if (was_nonblocking) {
        if (debug_enabled()) {
            log_debugf("Preserving non-blocking connect semantics after SOCKS5 handshake");
        }
        errno = EINPROGRESS;
        return -1;
    }

    return 0;
}

static int wrapguard_connect_impl(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    init_library();
    if (passthrough_mode_cached) {
#ifdef __APPLE__
        return raw_connect_call(sockfd, addr, addrlen);
#else
        return call_real_connect(sockfd, addr, addrlen);
#endif
    }

    if (addr == NULL || addrlen < (socklen_t)sizeof(addr->sa_family)) {
#ifdef __APPLE__
        return raw_connect_call(sockfd, addr, addrlen);
#else
        return call_real_connect(sockfd, addr, addrlen);
#endif
    }

    if (internal_connect_guard > 0) {
#ifdef __APPLE__
        return raw_connect_call(sockfd, addr, addrlen);
#else
        return call_real_connect(sockfd, addr, addrlen);
#endif
    }

    int sock_type = 0;
    socklen_t sock_type_len = sizeof(sock_type);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &sock_type_len) != 0) {
        if (debug_enabled()) {
            log_debugf("Failed to read socket type for fd=%d: %s", sockfd, strerror(errno));
        }
#ifdef __APPLE__
        return raw_connect_call(sockfd, addr, addrlen);
#else
        return call_real_connect(sockfd, addr, addrlen);
#endif
    }
    
    char addr_str[INET6_ADDRSTRLEN + 32];
    format_sockaddr(addr, addr_str, sizeof(addr_str));
    int suppress_debug_log = addr->sa_family == AF_UNIX && sock_type == SOCK_DGRAM;
    
    if (debug_enabled() && !suppress_debug_log) {
        log_debugf("connect() called for %s family=%s type=%s", addr_str, family_name(addr->sa_family), socket_type_name(sock_type));
    }

    if (sock_type == SOCK_DGRAM && should_block_udp_target(addr)) {
        if (debug_enabled()) {
            log_debugf("Blocking likely QUIC UDP flow to %s", addr_str);
        }
        forget_virtual_peer(sockfd);
        errno = EHOSTUNREACH;
        return -1;
    }

    if (sock_type != SOCK_STREAM) {
        if (debug_enabled() && !suppress_debug_log) {
            log_debugf("NOT intercepting %s because socket type is %s", addr_str, socket_type_name(sock_type));
        }
        forget_virtual_peer(sockfd);
#ifdef __APPLE__
        return raw_connect_call(sockfd, addr, addrlen);
#else
        return call_real_connect(sockfd, addr, addrlen);
#endif
    }
    
    if (!should_intercept_connect(addr)) {
        if (debug_enabled() && !suppress_debug_log) {
            log_debugf("NOT intercepting %s family=%s", addr_str, family_name(addr->sa_family));
        }
        forget_virtual_peer(sockfd);
#ifdef __APPLE__
        return raw_connect_call(sockfd, addr, addrlen);
#else
        return call_real_connect(sockfd, addr, addrlen);
#endif
    }
    
    if (debug_enabled()) {
        log_debugf("INTERCEPTING %s, routing through SOCKS5", addr_str);
    }
    
    send_ipc_message("CONNECT", sockfd, 0, addr_str);
    return socks5_connect(sockfd, addr, addrlen);
}

static int wrapguard_bind_impl(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    init_library();
    if (passthrough_mode_cached) {
#ifdef __APPLE__
        return raw_bind_call(sockfd, addr, addrlen);
#else
        return call_real_bind(sockfd, addr, addrlen);
#endif
    }

    if (addr == NULL || addrlen < (socklen_t)sizeof(addr->sa_family)) {
        return call_real_bind(sockfd, addr, addrlen);
    }
    
    int result = call_real_bind(sockfd, addr, addrlen);
    
    if (result == 0 && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        int port = 0;
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
            port = ntohs(in_addr->sin_port);
        } else {
            struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)addr;
            port = ntohs(in6_addr->sin6_port);
        }
        
        if (port == 0) {
            struct sockaddr_storage actual_addr;
            socklen_t actual_len = sizeof(actual_addr);
            if (getsockname(sockfd, (struct sockaddr *)&actual_addr, &actual_len) == 0) {
                if (actual_addr.ss_family == AF_INET) {
                    port = ntohs(((struct sockaddr_in *)&actual_addr)->sin_port);
                } else if (actual_addr.ss_family == AF_INET6) {
                    port = ntohs(((struct sockaddr_in6 *)&actual_addr)->sin6_port);
                }
            }
        }
        
        int sock_type = 0;
        socklen_t opt_len = sizeof(sock_type);
        if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &opt_len) == 0 && sock_type == SOCK_STREAM) {
            send_ipc_message("BIND", sockfd, port, NULL);
        }
    }
    
    return result;
}

#ifdef __APPLE__
static int wrapguard_connectx_impl(int sockfd, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid) {
    init_library();
    if (passthrough_mode_cached) {
        return raw_connectx_call(sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);
    }

    if (endpoints == NULL || endpoints->sae_dstaddr == NULL || endpoints->sae_dstaddrlen < (socklen_t)sizeof(sa_family_t)) {
        return call_real_connectx(sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);
    }

    if (internal_connect_guard > 0) {
        return call_real_connectx(sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);
    }

    if (endpoints->sae_srcif != 0 || endpoints->sae_srcaddr != NULL || endpoints->sae_srcaddrlen != 0 || iov != NULL || iovcnt != 0 || associd != SAE_ASSOCID_ANY || flags != 0) {
        if (debug_enabled()) {
            log_debugf("Falling back to real connectx() because advanced endpoints/options are in use");
        }
        return call_real_connectx(sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);
    }

    if (len != NULL) {
        *len = 0;
    }
    if (connid != NULL) {
        *connid = SAE_CONNID_ANY;
    }

    return wrapguard_connect_impl(sockfd, endpoints->sae_dstaddr, endpoints->sae_dstaddrlen);
}
#endif

 #ifndef __APPLE__
static int wrapguard_getpeername_impl(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    init_library();
    if (passthrough_mode_cached) {
        return call_real_getpeername(sockfd, addr, addrlen);
    }

    if (lookup_virtual_peer(sockfd, addr, addrlen)) {
        return 0;
    }

    return call_real_getpeername(sockfd, addr, addrlen);
}
#endif

static int wrapguard_close_impl(int fd) {
    if (initialized) {
        forget_virtual_peer(fd);
    }
    return call_real_close(fd);
}

#ifdef __APPLE__
static int wrapguard_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return wrapguard_connect_impl(sockfd, addr, addrlen);
}

static int wrapguard_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return wrapguard_bind_impl(sockfd, addr, addrlen);
}

static int wrapguard_connectx(int sockfd, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid) {
    return wrapguard_connectx_impl(sockfd, endpoints, associd, flags, iov, iovcnt, len, connid);
}

static ssize_t wrapguard_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    return wrapguard_sendto_impl(sockfd, buf, len, flags, dest_addr, addrlen);
}

static ssize_t wrapguard_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    return wrapguard_sendmsg_impl(sockfd, msg, flags);
}

static int wrapguard_close(int fd) {
    return wrapguard_close_impl(fd);
}

DYLD_INTERPOSE(wrapguard_connect, connect)
DYLD_INTERPOSE(wrapguard_bind, bind)
DYLD_INTERPOSE(wrapguard_connectx, connectx)
DYLD_INTERPOSE(wrapguard_sendto, sendto)
DYLD_INTERPOSE(wrapguard_sendmsg, sendmsg)
DYLD_INTERPOSE(wrapguard_close, close)
#else
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return wrapguard_connect_impl(sockfd, addr, addrlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return wrapguard_bind_impl(sockfd, addr, addrlen);
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    return wrapguard_getpeername_impl(sockfd, addr, addrlen);
}

int close(int fd) {
    return wrapguard_close_impl(fd);
}

#endif
