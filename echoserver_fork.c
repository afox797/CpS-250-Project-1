/* Echo Server: an example usage of EzNet
 *
 * This version is a start at a multiprocessing server. However,
 * it is incomplete. Zombies will start to stack up...
 * (c) 2016, Bob Jones University
 */
#include <stdbool.h>    // For access to C99 "bool" type
#include <stdio.h>      // Standard I/O functions
#include <stdlib.h>     // Other standard library functions
#include <string.h>     // Standard string functions
#include <errno.h>      // Global errno variable

#include <stdarg.h>     // Variadic argument lists (for blog function)
#include <time.h>       // Time/date formatting function (for blog function)

#include <unistd.h>     // Standard system calls
#include <signal.h>     // Signal handling system calls (sigaction(2))

#include "eznet.h"      // Custom networking library

// Generic log-to-stdout logging routine
// Message format: "timestamp:pid:user-defined-message"
void blog(const char *fmt, ...) {
    // Convert user format string and variadic args into a fixed string buffer
    char user_msg_buff[256];
    va_list vargs;
    va_start(vargs, fmt);
    vsnprintf(user_msg_buff, sizeof(user_msg_buff), fmt, vargs);
    va_end(vargs);

    // Get the current time as a string
    time_t t = time(NULL);
    struct tm *tp = localtime(&t);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tp);

    // Print said string to STDOUT prefixed by our timestamp and pid indicators
    printf("%s:%d:%s\n", timestamp, getpid(), user_msg_buff);
    fflush(stdout);    
}

// GLOBAL: settings structure instance
struct settings {
    const char *bindhost;   // Hostname/IP address to bind/listen on
    const char *bindport;   // Portnumber (as a string) to bind/listen on
} g_settings = {
    .bindhost = "localhost",    // Default: listen only on localhost interface
    .bindport = "6000",         // Default: listen on TCP port 5000
};

// Parse commandline options and sets g_settings accordingly.
// Returns 0 on success, -1 on false...
int parse_options(int argc, char * const argv[]) {
    int ret = -1; 

    char op;
    while ((op = getopt(argc, argv, "h:p:")) > -1) {
        switch (op) {
            case 'h':
                g_settings.bindhost = optarg;
                break;
            case 'p':
                g_settings.bindport = optarg;
                break;
            default:
                // Unexpected argument--abort parsing
                goto cleanup;
        }
    }

    ret = 0;
cleanup:
    return ret;
}

// GLOBAL: flag indicating when to shut down server
volatile bool server_running = false;

// SIGINT handler that detects Ctrl-C and sets the "stop serving" flag
void sigint_handler(int signum) {
    blog("Ctrl-C (SIGINT) detected; shutting down...");
    server_running = false;
}

// Connection handling logic: reads/echos lines of text until error/EOF,
// then tears down connection.
void handle_client(struct client_info *client) {
    FILE *stream = NULL;

    // Wrap the socket file descriptor in a read/write FILE stream
    // so we can use tasty stdio functions like getline(3)
    // [dup(2) the file descriptor so that we don't double-close;
    // fclose(3) will close the underlying file descriptor,
    // and so will destroy_client()]
    if ((stream = fdopen(dup(client->fd), "r+"))== NULL) {
        perror("unable to wrap socket");
        goto cleanup;
    }

    // Echo all lines
    char *line = NULL;
    size_t len = 0u;
    ssize_t recd;
    while ((recd = getline(&line, &len, stream)) > 0) {
        printf("\tReceived %zd byte line; echoing...\n", recd);
        fputs(line, stream); 
    }

cleanup:
    // Shutdown this client
    if (stream) fclose(stream);
    destroy_client_info(client);
    free(line);
    printf("\tSession ended.\n");
    exit(0);
}

int main(int argc, char **argv) {
    int ret = 1;

    // Network server/client context
    int server_sock = -1;

    // Handle our options
    if (parse_options(argc, argv)) {
        printf("usage: %s [-p PORT] [-h HOSTNAME/IP]\n", argv[0]);
        goto cleanup;
    }

    // Install signal handler for SIGINT
    struct sigaction sa_int = {
        .sa_handler = sigint_handler
    };
    if (sigaction(SIGINT, &sa_int, NULL)) {
        LOG_ERROR("sigaction(SIGINT, ...) -> '%s'", strerror(errno));
        goto cleanup;
    }

    // Start listening on a given port number
    server_sock = create_tcp_server(g_settings.bindhost, g_settings.bindport);
    if (server_sock < 0) {
        perror("unable to create socket");
        goto cleanup;
    }
    blog("Bound and listening on %s:%s", g_settings.bindhost, g_settings.bindport);

    server_running = true;
    while (server_running) {
        struct client_info client;

        // Wait for a connection on that socket
        if (wait_for_client(server_sock, &client)) {
            // Check to make sure our "failure" wasn't due to
            // a signal interrupting our accept(2) call; if
            // it was  "real" error, report it, but keep serving.
            if (errno != EINTR) { perror("unable to accept connection"); }
        } else {
            blog("connection from %s:%d", client.ip, client.port);
            if (fork()) {
                // I am the parent
                destroy_client_info(&client);
            } else {
                // I am the child
                close(server_sock);
                handle_client(&client); // Client gets cleaned up in here
            }
        }
    }
    ret = 0;

cleanup:
    if (server_sock >= 0) close(server_sock);
    return ret;
}

