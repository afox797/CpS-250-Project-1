#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// Create a socket(2) and connect(2) to <connecthost>:<connectport>.
// On success, return the connected socket's file descriptor.
// On error, return -1.
int create_tcp_client(const char *connecthost, const char *connectport) {
    int ret = -1;
    struct addrinfo *ai = NULL;
    int sock = -1;

    struct addrinfo hints = {
        .ai_socktype = SOCK_STREAM  // TCP only
    };

    // Look up target host/port names
    int gai_ret = getaddrinfo(connecthost, connectport, &hints, &ai);
    if (gai_ret) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_ret));
        goto cleanup;
    }

    // Try them one by one until one works (or all fail)
    for (struct addrinfo *try = ai; try; try = try->ai_next) {
        if ((sock = socket(try->ai_family, try->ai_socktype, try->ai_protocol)) < 0) {
            continue;   // Try the next entry in the name list
        } 
        if (connect(sock, try->ai_addr, try->ai_addrlen)) {
            close(sock);    // Close this socket and try the next entry
            sock = -1;
            continue;
        }

        // SUCCESS!  Break out of loop...
        break;
    }
    if (sock < 0) {
        // Something went wrong
        perror("socket/connect");
        goto cleanup;
    }

    ret = sock;
    sock = -1;      // In case sock was not -1, avoid closing the fd we return!
cleanup:
    if (sock >= 0) { close(sock); }
    if (ai) { freeaddrinfo(ai); }
    return ret;
}

int my_getline(int fd, char *buf, size_t max_len) {
    size_t pos = 0;

    int result;

    while ((result = read(fd, buf + pos, 1)) == 1 && buf[pos] != '\n' && pos < max_len - 1) {
        ++pos;
    }
    if (result && buf[pos] == '\n') pos++;
    buf[pos] = '\0';
    return result == 1;
}

int main(int argc, char **argv) {
    int ret = 1;
    int sock = -1;
    char buf[80];

    if (argc < 3) {
        fprintf(stderr, "usage: %s HOST PORT\n", argv[0]);
        goto cleanup;
    }

    if ((sock = create_tcp_client(argv[1], argv[2])) < 0) {
        fprintf(stderr, "Failed to connect to %s:%s; aborting...\n", argv[1], argv[2]);
        goto cleanup;
    }

    while (fgets(buf, sizeof(buf), stdin) > 0) {
        if (write(sock, buf, strlen(buf)) == EOF) {
            perror("fputs");
            goto cleanup;
        }
        if (my_getline(sock, buf, sizeof(buf)) <= 0) {
            perror("getline");
            goto cleanup;
        }
        printf("Received: %s", buf);
    }
    if (ferror(stdin)) {    // Did the loop end because of errors?
        perror("getline");
        goto cleanup;
    }

    ret = 0;
cleanup:
    if (sock >= 0) { close(sock); }
    return ret;
}

