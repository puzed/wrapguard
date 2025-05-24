#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>

// JSON parsing would normally use a library, but for simplicity, we'll use a basic approach
typedef struct {
    char type[32];
    uint32_t conn_id;
    int socket_fd;
    int domain;
    int sock_type;
    int protocol;
    char address[64];
    int port;
    size_t data_len;
    char *data;
    char error[256];
} IPCMessage;

typedef struct {
    int success;
    uint32_t conn_id;
    size_t data_len;
    char *data;
    char error[256];
} IPCResponse;

// Connection mapping
typedef struct {
    int fd;
    uint32_t conn_id;
} FDMapping;

static FDMapping fd_mappings[1024];
static int next_fake_fd = 1000;
static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;
static int ipc_socket = -1;
static char ipc_path[256];

// Function pointers to real functions
static int (*real_socket)(int domain, int type, int protocol);
static int (*real_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*real_listen)(int sockfd, int backlog);
static int (*real_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*real_sendto)(int sockfd, const void *buf, size_t len, int flags,
                               const struct sockaddr *dest_addr, socklen_t addrlen);
static ssize_t (*real_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                                 struct sockaddr *src_addr, socklen_t *addrlen);
static int (*real_close)(int fd);

// Initialize the library
__attribute__((constructor))
void init_intercept() {
    // Get real function pointers
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_bind = dlsym(RTLD_NEXT, "bind");
    real_listen = dlsym(RTLD_NEXT, "listen");
    real_accept = dlsym(RTLD_NEXT, "accept");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_close = dlsym(RTLD_NEXT, "close");

    // Get IPC socket path from environment
    const char *path = getenv("WRAPGUARD_IPC_PATH");
    if (path) {
        strncpy(ipc_path, path, sizeof(ipc_path) - 1);
        ipc_path[sizeof(ipc_path) - 1] = '\0';
    }

    // Initialize FD mappings
    memset(fd_mappings, 0, sizeof(fd_mappings));
}

// Connect to IPC server
static int connect_ipc() {
    if (ipc_socket >= 0) {
        return ipc_socket;
    }

    ipc_socket = real_socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipc_socket < 0) {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ipc_path, sizeof(addr.sun_path) - 1);

    if (real_connect(ipc_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        real_close(ipc_socket);
        ipc_socket = -1;
        return -1;
    }

    return ipc_socket;
}

// Simple JSON serialization helpers
static void write_json_string(char *buf, size_t *pos, const char *key, const char *value) {
    *pos += snprintf(buf + *pos, 4096 - *pos, "\"%s\":\"%s\",", key, value);
}

static void write_json_int(char *buf, size_t *pos, const char *key, int value) {
    *pos += snprintf(buf + *pos, 4096 - *pos, "\"%s\":%d,", key, value);
}

static void write_json_uint32(char *buf, size_t *pos, const char *key, uint32_t value) {
    *pos += snprintf(buf + *pos, 4096 - *pos, "\"%s\":%u,", key, value);
}

// Send IPC message and get response
static int send_ipc_message(IPCMessage *msg, IPCResponse *resp) {
    int sock = connect_ipc();
    if (sock < 0) {
        return -1;
    }

    // Build JSON message
    char json_buf[4096];
    size_t pos = 0;
    
    json_buf[pos++] = '{';
    write_json_string(json_buf, &pos, "type", msg->type);
    
    if (msg->conn_id > 0) {
        write_json_uint32(json_buf, &pos, "conn_id", msg->conn_id);
    }
    if (msg->socket_fd > 0) {
        write_json_int(json_buf, &pos, "socket_fd", msg->socket_fd);
    }
    if (msg->domain > 0) {
        write_json_int(json_buf, &pos, "domain", msg->domain);
    }
    if (msg->sock_type > 0) {
        write_json_int(json_buf, &pos, "sock_type", msg->sock_type);
    }
    if (msg->protocol >= 0) {
        write_json_int(json_buf, &pos, "protocol", msg->protocol);
    }
    if (strlen(msg->address) > 0) {
        write_json_string(json_buf, &pos, "address", msg->address);
    }
    if (msg->port > 0) {
        write_json_int(json_buf, &pos, "port", msg->port);
    }
    
    // Remove trailing comma and close JSON
    if (json_buf[pos-1] == ',') pos--;
    json_buf[pos++] = '}';
    json_buf[pos++] = '\n';
    json_buf[pos] = '\0';

    // Send message
    if (write(sock, json_buf, pos) < 0) {
        return -1;
    }

    // Read response (simplified parsing)
    char resp_buf[4096];
    ssize_t n = read(sock, resp_buf, sizeof(resp_buf) - 1);
    if (n <= 0) {
        return -1;
    }
    resp_buf[n] = '\0';

    // Parse response (very basic)
    resp->success = (strstr(resp_buf, "\"success\":true") != NULL);
    
    char *conn_id_str = strstr(resp_buf, "\"conn_id\":");
    if (conn_id_str) {
        resp->conn_id = atoi(conn_id_str + 10);
    }

    char *error_str = strstr(resp_buf, "\"error\":\"");
    if (error_str) {
        error_str += 9;
        char *end = strchr(error_str, '"');
        if (end) {
            size_t len = end - error_str;
            if (len > sizeof(resp->error) - 1) {
                len = sizeof(resp->error) - 1;
            }
            strncpy(resp->error, error_str, len);
            resp->error[len] = '\0';
        }
    }

    return 0;
}

// Map connection ID to fake FD
static int map_conn_to_fd(uint32_t conn_id) {
    pthread_mutex_lock(&fd_mutex);
    
    int fd = next_fake_fd++;
    if (fd < 1024) {
        fd_mappings[fd].fd = fd;
        fd_mappings[fd].conn_id = conn_id;
    }
    
    pthread_mutex_unlock(&fd_mutex);
    return fd;
}

// Get connection ID from FD
static uint32_t get_conn_id(int fd) {
    if (fd < 1000 || fd >= 1024) {
        return 0;
    }
    
    pthread_mutex_lock(&fd_mutex);
    uint32_t conn_id = fd_mappings[fd].conn_id;
    pthread_mutex_unlock(&fd_mutex);
    
    return conn_id;
}

// Intercepted functions
int socket(int domain, int type, int protocol) {
    // Only intercept AF_INET sockets
    if (domain != AF_INET) {
        return real_socket(domain, type, protocol);
    }

    IPCMessage msg = {0};
    IPCResponse resp = {0};
    
    strcpy(msg.type, "socket");
    msg.domain = domain;
    msg.sock_type = type;
    msg.protocol = protocol;

    if (send_ipc_message(&msg, &resp) < 0 || !resp.success) {
        errno = ENOTSUP;
        return -1;
    }

    return map_conn_to_fd(resp.conn_id);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    uint32_t conn_id = get_conn_id(sockfd);
    if (conn_id == 0) {
        return real_bind(sockfd, addr, addrlen);
    }

    if (addr->sa_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    
    IPCMessage msg = {0};
    IPCResponse resp = {0};
    
    strcpy(msg.type, "bind");
    msg.conn_id = conn_id;
    inet_ntop(AF_INET, &sin->sin_addr, msg.address, sizeof(msg.address));
    msg.port = ntohs(sin->sin_port);

    if (send_ipc_message(&msg, &resp) < 0 || !resp.success) {
        errno = EADDRINUSE;
        return -1;
    }

    return 0;
}

int listen(int sockfd, int backlog) {
    uint32_t conn_id = get_conn_id(sockfd);
    if (conn_id == 0) {
        return real_listen(sockfd, backlog);
    }

    IPCMessage msg = {0};
    IPCResponse resp = {0};
    
    strcpy(msg.type, "listen");
    msg.conn_id = conn_id;

    if (send_ipc_message(&msg, &resp) < 0 || !resp.success) {
        errno = EOPNOTSUPP;
        return -1;
    }

    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    uint32_t conn_id = get_conn_id(sockfd);
    if (conn_id == 0) {
        return real_accept(sockfd, addr, addrlen);
    }

    IPCMessage msg = {0};
    IPCResponse resp = {0};
    
    strcpy(msg.type, "accept");
    msg.conn_id = conn_id;

    if (send_ipc_message(&msg, &resp) < 0 || !resp.success) {
        errno = EAGAIN;
        return -1;
    }

    // TODO: Fill in addr if provided
    
    return map_conn_to_fd(resp.conn_id);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    uint32_t conn_id = get_conn_id(sockfd);
    if (conn_id == 0) {
        return real_connect(sockfd, addr, addrlen);
    }

    if (addr->sa_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    
    IPCMessage msg = {0};
    IPCResponse resp = {0};
    
    strcpy(msg.type, "connect");
    msg.conn_id = conn_id;
    inet_ntop(AF_INET, &sin->sin_addr, msg.address, sizeof(msg.address));
    msg.port = ntohs(sin->sin_port);

    if (send_ipc_message(&msg, &resp) < 0 || !resp.success) {
        errno = ECONNREFUSED;
        return -1;
    }

    return 0;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    uint32_t conn_id = get_conn_id(sockfd);
    if (conn_id == 0) {
        return real_send(sockfd, buf, len, flags);
    }

    IPCMessage msg = {0};
    IPCResponse resp = {0};
    
    strcpy(msg.type, "send");
    msg.conn_id = conn_id;
    msg.data = (char *)buf;
    msg.data_len = len;

    if (send_ipc_message(&msg, &resp) < 0 || !resp.success) {
        errno = EPIPE;
        return -1;
    }

    return len;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    uint32_t conn_id = get_conn_id(sockfd);
    if (conn_id == 0) {
        return real_recv(sockfd, buf, len, flags);
    }

    IPCMessage msg = {0};
    IPCResponse resp = {0};
    
    strcpy(msg.type, "recv");
    msg.conn_id = conn_id;

    if (send_ipc_message(&msg, &resp) < 0 || !resp.success) {
        if (flags & MSG_DONTWAIT) {
            errno = EAGAIN;
        } else {
            errno = ECONNRESET;
        }
        return -1;
    }

    // Copy received data
    size_t copy_len = resp.data_len < len ? resp.data_len : len;
    if (resp.data && copy_len > 0) {
        memcpy(buf, resp.data, copy_len);
    }

    return copy_len;
}

int close(int fd) {
    uint32_t conn_id = get_conn_id(fd);
    if (conn_id == 0) {
        return real_close(fd);
    }

    IPCMessage msg = {0};
    IPCResponse resp = {0};
    
    strcpy(msg.type, "close");
    msg.conn_id = conn_id;

    send_ipc_message(&msg, &resp);

    // Remove mapping
    pthread_mutex_lock(&fd_mutex);
    if (fd < 1024) {
        fd_mappings[fd].conn_id = 0;
    }
    pthread_mutex_unlock(&fd_mutex);

    return 0;
}

// Also intercept sendto and recvfrom for UDP
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    uint32_t conn_id = get_conn_id(sockfd);
    if (conn_id == 0) {
        return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    // For UDP, we might need to handle destination address
    return send(sockfd, buf, len, flags);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    uint32_t conn_id = get_conn_id(sockfd);
    if (conn_id == 0) {
        return real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    }

    // For UDP, we might need to fill in source address
    return recv(sockfd, buf, len, flags);
}
