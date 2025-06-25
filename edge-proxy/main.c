#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include "config.h"
#include "waf_engine.h"

#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192
#define MAX_BACKEND_SERVERS 10
#define PROXY_HEADER "X-Forwarded-For"

typedef struct {
    int client_fd;
    int backend_fd;
    SSL *client_ssl;
    SSL *backend_ssl;
    char client_ip[INET6_ADDRSTRLEN];
    char buffer[BUFFER_SIZE];
    size_t buffer_len;
    time_t last_activity;
} proxy_connection_t;

typedef struct {
    char host[256];
    int port;
    int is_ssl;
} backend_server_t;

typedef struct {
    int listen_fd;
    int epoll_fd;
    int running;
    backend_server_t backends[MAX_BACKEND_SERVERS];
    int backend_count;
    SSL_CTX *ssl_ctx;
    waf_engine_t *waf;
} proxy_context_t;

// Global context
proxy_context_t ctx;

// Function prototypes
void init_proxy();
void cleanup_proxy();
void handle_signal(int sig);
int setup_listener(int port, int is_ssl);
int setup_epoll();
int add_to_epoll(int fd, uint32_t events);
void run_event_loop();
void handle_new_connection();
void handle_client_data(int fd);
void handle_backend_data(int fd);
void close_connection(proxy_connection_t *conn);
int connect_to_backend(backend_server_t *backend);
int load_backends_from_config(const char *config_file);
SSL_CTX *create_ssl_context(const char *cert_path, const char *key_path);
void log_request(const char *client_ip, const char *method, const char *uri);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Initialize signal handling
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    // Initialize proxy components
    init_proxy();

    // Load configuration
    if (load_backends_from_config(argv[1]) {
        fprintf(stderr, "Failed to load configuration\n");
        cleanup_proxy();
        exit(EXIT_FAILURE);
    }

    // Initialize WAF
    ctx.waf = waf_init();
    if (!ctx.waf) {
        fprintf(stderr, "Failed to initialize WAF engine\n");
        cleanup_proxy();
        exit(EXIT_FAILURE);
    }

    // Setup listener (both HTTP and HTTPS)
    ctx.listen_fd = setup_listener(DEFAULT_HTTP_PORT, 0);
    if (ctx.listen_fd < 0) {
        cleanup_proxy();
        exit(EXIT_FAILURE);
    }

    // Setup epoll
    ctx.epoll_fd = setup_epoll();
    if (ctx.epoll_fd < 0) {
        cleanup_proxy();
        exit(EXIT_FAILURE);
    }

    // Add listener to epoll
    if (add_to_epoll(ctx.listen_fd, EPOLLIN | EPOLLET) < 0) {
        cleanup_proxy();
        exit(EXIT_FAILURE);
    }

    printf("Proxy server started successfully\n");
    printf("Listening on port %d (HTTP)\n", DEFAULT_HTTP_PORT);

    // Main event loop
    run_event_loop();

    // Cleanup
    cleanup_proxy();
    return 0;
}

void init_proxy() {
    memset(&ctx, 0, sizeof(proxy_context_t));
    ctx.running = 1;

    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create SSL context (for HTTPS backends)
    ctx.ssl_ctx = create_ssl_context(NULL, NULL);
    if (!ctx.ssl_ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        exit(EXIT_FAILURE);
    }
}

void cleanup_proxy() {
    printf("\nShutting down proxy server...\n");

    // Close all file descriptors
    if (ctx.listen_fd > 0) {
        close(ctx.listen_fd);
    }

    if (ctx.epoll_fd > 0) {
        close(ctx.epoll_fd);
    }

    // Cleanup OpenSSL
    if (ctx.ssl_ctx) {
        SSL_CTX_free(ctx.ssl_ctx);
    }
    EVP_cleanup();

    // Cleanup WAF
    if (ctx.waf) {
        waf_cleanup(ctx.waf);
    }
}

void handle_signal(int sig) {
    printf("Received signal %d, shutting down...\n", sig);
    ctx.running = 0;
}

int setup_listener(int port, int is_ssl) {
    int fd;
    struct sockaddr_in addr;
    int opt = 1;

    // Create socket
    if ((fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0) {
        perror("socket");
        return -1;
    }

    // Set SO_REUSEADDR
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    // Bind to port
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    // Listen for connections
    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

int setup_epoll() {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
    }
    return epoll_fd;
}

int add_to_epoll(int fd, uint32_t events) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        perror("epoll_ctl");
        return -1;
    }
    return 0;
}

void run_event_loop() {
    struct epoll_event events[MAX_EVENTS];
    int n, i;

    while (ctx.running) {
        n = epoll_wait(ctx.epoll_fd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            break;
        }

        for (i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == ctx.listen_fd) {
                handle_new_connection();
            } else {
                if (events[i].events & EPOLLIN) {
                    handle_client_data(fd);
                } else if (events[i].events & EPOLLOUT) {
                    handle_backend_data(fd);
                } else if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {

                    close(fd);
                }
            }
        }
    }
}

void handle_new_connection() {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;
    proxy_connection_t *conn;

    while ((client_fd = accept(ctx.listen_fd, (struct sockaddr *)&addr, &addr_len)) > 0) {
        // Set non-blocking
        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

        // Create new connection context
        conn = calloc(1, sizeof(proxy_connection_t));
        if (!conn) {
            close(client_fd);
            continue;
        }

        conn->client_fd = client_fd;
        conn->last_activity = time(NULL);
        inet_ntop(AF_INET, &addr.sin_addr, conn->client_ip, INET6_ADDRSTRLEN);

        // Add to epoll
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
        ev.data.ptr = conn;

        if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            perror("epoll_ctl");
            free(conn);
            close(client_fd);
            continue;
        }

        printf("New connection from %s\n", conn->client_ip);
    }

    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
    }
}

void handle_client_data(int fd) {
    proxy_connection_t *conn = NULL;
    struct epoll_event ev;
    ssize_t n;

    // Find connection context (in a real implementation you should have a proper lookup)
    // For simplicity, let us assume the data is in the event structure
    // In production, you should maintain a proper connection tracking system

    // Read data from client
    char buffer[BUFFER_SIZE];
    n = read(fd, buffer, sizeof(buffer));
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
        close(fd);
        return;
    }

    // Process HTTP request
    char *method = strtok(buffer, " ");
    char *uri = strtok(NULL, " ");

    if (method && uri) {
        log_request("client_ip", method, uri);

        // WAF Inspection
        waf_http_request_t waf_req = {
            .method = method,
            .uri = uri,
            .headers = NULL,
            .body = NULL,
            .body_length = 0,
            .remote_ip = "client_ip"
        };

        waf_action_t action = waf_process_request(ctx.waf, &waf_req);
        switch (action) {
            case WAF_ACTION_BLOCK:
                printf("Blocking malicious request: %s %s\n", method, uri);
                const char *response = "HTTP/1.1 403 Forbidden\r\n"
                                      "Content-Length: 0\r\n"
                                      "Connection: close\r\n\r\n";
                write(fd, response, strlen(response));
                close(fd);
                return;
            case WAF_ACTION_CHALLENGE:
                // Implement CAPTCHA challenge
                break;
            case WAF_ACTION_LOG:
                // Log suspicious request
                break;
            case WAF_ACTION_ALLOW:
                // Continue processing
                break;
        }
    }

    // Select backend (round-robin in this simple example)
    static int current_backend = 0;
    backend_server_t *backend = &ctx.backends[current_backend];
    current_backend = (current_backend + 1) % ctx.backend_count;

    // Connect to backend
    int backend_fd = connect_to_backend(backend);
    if (backend_fd < 0) {
        const char *response = "HTTP/1.1 502 Bad Gateway\r\n"
                              "Content-Length: 0\r\n"
                              "Connection: close\r\n\r\n";
        write(fd, response, strlen(response));
        close(fd);
        return;
    }

    // Forward request to backend
    write(backend_fd, buffer, n);

    // Setup connection context (simplified)
    conn = calloc(1, sizeof(proxy_connection_t));
    conn->client_fd = fd;
    conn->backend_fd = backend_fd;
    conn->last_activity = time(NULL);

    // Add both ends to epoll
    ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = conn;
    epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = conn;
    epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, backend_fd, &ev);
}

void handle_backend_data(int fd) {
    char buffer[BUFFER_SIZE];
    ssize_t n;

    // Read data from backend
    n = read(fd, buffer, sizeof(buffer));
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
        close(fd);
        return;
    }

    // Forward to client (simplified - in reality you should track the connection)
    proxy_connection_t *conn = NULL;  // Should get from context
    if (conn) {
        write(conn->client_fd, buffer, n);
    }
}

int connect_to_backend(backend_server_t *backend) {
    struct sockaddr_in addr;
    struct hostent *he;
    int fd;

    if ((he = gethostbyname(backend->host)) == NULL) {
        perror("gethostbyname");
        return -1;
    }

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(backend->port);
    addr.sin_addr = *((struct in_addr *)he->h_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

int load_backends_from_config(const char *config_file) {
    // In a real implementation, you'd parse the YAML config file
    // For this example, I have hardcoded some backends

    ctx.backend_count = 2;

    // Backend 1
    strncpy(ctx.backends[0].host, "127.0.0.1", sizeof(ctx.backends[0].host));
    ctx.backends[0].port = 8080;
    ctx.backends[0].is_ssl = 0;

    // Backend 2
    strncpy(ctx.backends[1].host, "127.0.0.1", sizeof(ctx.backends[1].host));
    ctx.backends[1].port = 8081;
    ctx.backends[1].is_ssl = 0;

    return 0;
}

SSL_CTX *create_ssl_context(const char *cert_path, const char *key_path) {
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Configure SSL context
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    // Load certificate and private key
    if (cert_path && key_path) {
        if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }

        if (!SSL_CTX_check_private_key(ctx)) {
            fprintf(stderr, "Private key does not match the certificate public key\n");
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    return ctx;
}

void log_request(const char *client_ip, const char *method, const char *uri) {
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    printf("[%s] %s - %s %s\n", timestamp, client_ip, method, uri);
}
