#define _GNU_SOURCE
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
#include <sys/time.h>

// Function pointers for original functions
static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*real_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;

// Global variables for configuration
static char *ipc_path = NULL;
static int socks_port = 0;
static int initialized = 0;

// Initialize the library
static void init_library() {
    if (initialized) return;
    initialized = 1;
    
    // Load original functions
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_bind = dlsym(RTLD_NEXT, "bind");
    
    // Get configuration from environment
    ipc_path = getenv("WRAPGUARD_IPC_PATH");
    char *socks_port_str = getenv("WRAPGUARD_SOCKS_PORT");
    if (socks_port_str) {
        socks_port = atoi(socks_port_str);
    }
    
    // Debug output (only in debug mode)
    char *debug_mode = getenv("WRAPGUARD_DEBUG");
    if (debug_mode && strcmp(debug_mode, "1") == 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Initialized\n");
        fprintf(stderr, "WrapGuard LD_PRELOAD: IPC path: %s\n", ipc_path ? ipc_path : "NULL");
        fprintf(stderr, "WrapGuard LD_PRELOAD: SOCKS port: %d\n", socks_port);
    }
    
    if (!ipc_path || socks_port == 0) {
        fprintf(stderr, "WrapGuard: Missing environment variables\n");
    }
}

// Check if an address should be intercepted
static int should_intercept_connect(const struct sockaddr *addr) {
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return 0; // Only intercept IP connections
    }
    
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        
        // Don't intercept localhost connections (except when connecting to our SOCKS proxy)
        uint32_t ip = ntohl(in_addr->sin_addr.s_addr);
        if ((ip & 0xFF000000) == 0x7F000000) { // 127.x.x.x
            int port = ntohs(in_addr->sin_port);
            if (port == socks_port) {
                return 0; // Don't intercept connections to our own SOCKS proxy
            }
        }
        
        return 1; // Intercept all other connections
    }
    
    // TODO: Handle IPv6 if needed
    return 0;
}

// Send IPC message
static void send_ipc_message(const char *type, int fd, int port, const char *addr) {
    if (!ipc_path) return;
    
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return;
    
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, ipc_path, sizeof(sun.sun_path) - 1);
    
    if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
        char message[512];
        snprintf(message, sizeof(message),
                "{\"type\":\"%s\",\"fd\":%d,\"port\":%d,\"addr\":\"%s\"}\n",
                type, fd, port, addr ? addr : "");
        
        write(sock, message, strlen(message));
    }
    
    close(sock);
}

// SOCKS5 connection helper
static int socks5_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char *debug_mode = getenv("WRAPGUARD_DEBUG");
    
    if (addr->sa_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    
    struct sockaddr_in *target = (struct sockaddr_in *)addr;
    struct sockaddr_in socks_addr;
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socks_addr.sin_port = htons(socks_port);
    
    // Connect to SOCKS5 proxy
    if (debug_mode && strcmp(debug_mode, "1") == 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Connecting to SOCKS5 proxy at 127.0.0.1:%d\n", socks_port);
    }
    int connect_result = real_connect(sockfd, (struct sockaddr *)&socks_addr, sizeof(socks_addr));
    if (connect_result != 0 && errno != EINPROGRESS) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Failed to connect to SOCKS5 proxy: %s\n", strerror(errno));
        return -1;
    }
    
    // For non-blocking sockets, we need to wait for connection to complete
    if (errno == EINPROGRESS) {
        if (debug_mode && strcmp(debug_mode, "1") == 0) {
            fprintf(stderr, "WrapGuard LD_PRELOAD: Non-blocking connect in progress, waiting...\n");
        }
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sockfd, &write_fds);
        
        struct timeval timeout = {5, 0}; // 5 second timeout
        int select_result = select(sockfd + 1, NULL, &write_fds, NULL, &timeout);
        if (select_result <= 0) {
            fprintf(stderr, "WrapGuard LD_PRELOAD: Timeout waiting for SOCKS5 connection\n");
            return -1;
        }
        
        // Check if connection actually succeeded
        int so_error;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) != 0 || so_error != 0) {
            fprintf(stderr, "WrapGuard LD_PRELOAD: SOCKS5 connection failed: %s\n", strerror(so_error));
            return -1;
        }
    }
    
    if (debug_mode && strcmp(debug_mode, "1") == 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Connected to SOCKS5 proxy, starting handshake\n");
    }
    
    // SOCKS5 handshake
    unsigned char handshake[] = {0x05, 0x01, 0x00}; // Version 5, 1 method, no auth
    if (debug_mode && strcmp(debug_mode, "1") == 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Sending SOCKS5 handshake\n");
    }
    if (send(sockfd, handshake, 3, 0) != 3) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Failed to send SOCKS5 handshake\n");
        return -1;
    }
    
    unsigned char response[2];
    if (debug_mode && strcmp(debug_mode, "1") == 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Waiting for SOCKS5 handshake response\n");
    }
    
    // Wait for response with timeout (non-blocking socket issue)
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);
    
    struct timeval timeout = {5, 0}; // 5 second timeout
    int select_result = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (select_result <= 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Timeout waiting for SOCKS5 handshake response\n");
        return -1;
    }
    
    int recv_bytes = recv(sockfd, response, 2, 0);
    if (recv_bytes != 2) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: SOCKS5 handshake response failed, got %d bytes, errno: %s\n", recv_bytes, strerror(errno));
        return -1;
    }
    if (response[0] != 0x05 || response[1] != 0x00) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Invalid SOCKS5 handshake response: %02x %02x\n", response[0], response[1]);
        return -1;
    }
    if (debug_mode && strcmp(debug_mode, "1") == 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: SOCKS5 handshake successful\n");
    }
    
    // SOCKS5 connect request
    unsigned char connect_req[10];
    connect_req[0] = 0x05; // Version
    connect_req[1] = 0x01; // Connect command
    connect_req[2] = 0x00; // Reserved
    connect_req[3] = 0x01; // IPv4 address type
    memcpy(&connect_req[4], &target->sin_addr, 4); // IP address
    memcpy(&connect_req[8], &target->sin_port, 2); // Port
    
    if (send(sockfd, connect_req, 10, 0) != 10) {
        return -1;
    }
    
    // Read SOCKS5 response with timeout
    unsigned char connect_resp[10];
    
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    select_result = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (select_result <= 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: Timeout waiting for SOCKS5 connect response\n");
        return -1;
    }
    
    if (recv(sockfd, connect_resp, 10, 0) != 10 || connect_resp[0] != 0x05 || connect_resp[1] != 0x00) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: SOCKS5 connect failed\n");
        errno = ECONNREFUSED;
        return -1;
    }
    
    return 0; // Success
}

// Intercepted connect function
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    init_library();
    
    // Convert address to string for logging
    char addr_str[INET_ADDRSTRLEN + 16];
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in_addr->sin_addr, ip_str, INET_ADDRSTRLEN);
        snprintf(addr_str, sizeof(addr_str), "%s:%d", ip_str, ntohs(in_addr->sin_port));
    } else {
        strcpy(addr_str, "unknown");
    }
    
    char *debug_mode = getenv("WRAPGUARD_DEBUG");
    if (debug_mode && strcmp(debug_mode, "1") == 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: connect() called for %s\n", addr_str);
    }
    
    if (!should_intercept_connect(addr)) {
        if (debug_mode && strcmp(debug_mode, "1") == 0) {
            fprintf(stderr, "WrapGuard LD_PRELOAD: NOT intercepting %s\n", addr_str);
        }
        return real_connect(sockfd, addr, addrlen);
    }
    
    if (debug_mode && strcmp(debug_mode, "1") == 0) {
        fprintf(stderr, "WrapGuard LD_PRELOAD: INTERCEPTING %s, routing through SOCKS5\n", addr_str);
    }
    
    // Send IPC message
    send_ipc_message("CONNECT", sockfd, 0, addr_str);
    
    // Route through SOCKS5
    return socks5_connect(sockfd, addr, addrlen);
}

// Intercepted bind function
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    init_library();
    
    // Call original bind first
    int result = real_bind(sockfd, addr, addrlen);
    
    // If bind succeeded and it's a TCP socket, notify the main process
    if (result == 0 && addr->sa_family == AF_INET) {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        int port = ntohs(in_addr->sin_port);
        
        // Get the actual port if it was auto-assigned (port 0)
        if (port == 0) {
            struct sockaddr_in actual_addr;
            socklen_t actual_len = sizeof(actual_addr);
            if (getsockname(sockfd, (struct sockaddr *)&actual_addr, &actual_len) == 0) {
                port = ntohs(actual_addr.sin_port);
            }
        }
        
        // Check if it's a TCP socket
        int sock_type;
        socklen_t opt_len = sizeof(sock_type);
        if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &opt_len) == 0 && sock_type == SOCK_STREAM) {
            // Send IPC message to set up port forwarding
            send_ipc_message("BIND", sockfd, port, NULL);
        }
    }
    
    return result;
}