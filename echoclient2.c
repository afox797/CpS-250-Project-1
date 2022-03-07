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

int main(int argc, char **argv) {
    int ret = 1;
    int sock = -1;
    FILE *sockstream = NULL;
    char *buff = NULL;
    size_t blen = 0u;

    if (argc < 3) {
        fprintf(stderr, "usage: %s HOST PORT\n", argv[0]);
        goto cleanup;
    }

    if ((sock = create_tcp_client(argv[1], argv[2])) < 0) {
        fprintf(stderr, "Failed to connect to %s:%s; aborting...\n", argv[1], argv[2]);
        goto cleanup;
    }

    if ((sockstream = fdopen(dup(sock), "r+")) == NULL) {
        perror("fdopen");
        goto cleanup;
    }

    while (getline(&buff, &blen, stdin) > 0) {
        if (fputs(buff, sockstream) == EOF) {
            perror("fputs");
            goto cleanup;
        }
        if (getline(&buff, &blen, sockstream) <= 0) {
            perror("getline");
            goto cleanup;
        }
        printf("Received: %s", buff);
    }
    if (ferror(stdin)) {    // Did the loop end because of errors?
        perror("getline");
        goto cleanup;
    }

    ret = 0;
cleanup:
    free(buff);
    if (sockstream) { fclose(sockstream); }
    if (sock >= 0) { close(sock); }
    return ret;
}

