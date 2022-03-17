/* Echo Server: an example usage of EzNet
 * (c) 2016, Bob Jones University
 */
#include <stdbool.h>    // For access to C99 "bool" type
#include <stdio.h>      // Standard I/O functions
#include <stdlib.h>     // Other standard library functions
#include <string.h>     // Standard string functions
#include <errno.h>      // Global errno variable
#include <sys/types.h>  // opendir function
#include <bsd/string.h> // Safe string functions

#include <stdarg.h>     // Variadic argument lists (for blog function)
#include <time.h>       // Time/date formatting function (for blog function)

#include <unistd.h>     // Standard system calls
#include <signal.h>     // Signal handling system calls (sigaction(2))
#include <dirent.h>

#include "eznet.h"      // Custom networking library
#include "utils.h"

#define RC_OK 1
#define RC_ILLEGAL_STREAM -1
#define RC_IO_ERROR -2
#define RC_MALLOC_FAILURE -3
#define RC_ILLEGAL_VERB -4
#define RC_ILLEGAL_PATH -5
#define RC_MISSING_VERSION -6
#define RC_OTHER_ERR -7

// GLOBAL: settings structure instance
struct settings {
    const char *bindhost;   // Hostname/IP address to bind/listen on
    const char *bindport;   // Portnumber (as a string) to bind/listen on
    const char *directory;
} g_settings = {
    .bindhost = "localhost",    // Default: listen only on localhost interface
    .bindport = "6000",         // Default: listen on TCP port 5000
    .directory = ".",       // Default: home directory
};

typedef struct http_request {
    char *verb;
    char *path;
    char *version;
} http_request_t;


// Parse commandline options and sets g_settings accordingly.
// Returns 0 on success, -1 on false...
int parse_options(int argc, char * const argv[]) {
    int ret = -1; 

    char op;
    while ((op = getopt(argc, argv, "h:p:r:")) > -1) {
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

// Returns RC_OK on success,
// RC_ILLEGAL_STREAM on invalid HTTP request,
// RC_IO_ERROR on I/O error,
// RC_MALLOC_FAILURE on malloc failure
int parseHttp(FILE *in, http_request_t **request)
{
    http_request_t *req = NULL;
    int rc = RC_OTHER_ERR;
    char *result;
    int BUFFER_SIZE = 400;

    char illegalChars[] = "\"\\\\~\\\"`!@#$%^&*()-_=+[{]}|;:'<>?,\"";

    if ((req = calloc(10, sizeof(http_request_t))) == NULL) {
        rc = RC_MALLOC_FAILURE;
    }

    char *buffer = malloc(BUFFER_SIZE);
    char *info_ptr;

    fgets(buffer, BUFFER_SIZE, in);
    req -> verb = strdup(strtok_r(buffer, " ", &info_ptr)); // assigning value to verb from the struct
    req -> path = strdup(strtok_r(NULL, " ", &info_ptr)); // strtok_r requires using NULL after first call
    req -> version = strdup(strtok_r(NULL, " ", &info_ptr));

    if (strcmp(req -> verb, "GET") == 0) {
    } else {
        rc = RC_ILLEGAL_VERB;
    }

    if (strpbrk(req -> path, illegalChars)) {
        rc = RC_ILLEGAL_PATH;
    }

    if (req -> version == NULL) {
        rc = RC_MISSING_VERSION;
    }

    if (strpbrk(req -> version, " ")) {
        rc = RC_MISSING_VERSION;
    }

    while (strcmp((result = fgets(buffer, BUFFER_SIZE, in)), "\r\n") != 0) {
        if (ferror(in)) {
            rc = RC_IO_ERROR;
        }
        if (result == NULL) {
            rc = RC_ILLEGAL_STREAM;
        }
    }


    if (feof(in)) {
        rc = RC_ILLEGAL_STREAM;
    }

    if (ferror(in)) {
        rc = RC_IO_ERROR;
    }


    blog("Path requested: %s\n", req->path);
    if (rc == RC_OTHER_ERR) {
        rc = RC_OK;
    }
    *request = req;

    free(buffer);
    return rc;
}

// Connection handling logic: reads/echos lines of text until error/EOF,
// then tears down connection.
void handle_client(struct client_info *client) {
    FILE *stream = NULL;
    http_request_t *request = NULL;
    // Wrap the socket file descriptor in a read/write FILE stream
    // so we can use tasty stdio functions like getline(3)
    // [dup(2) the file descriptor so that we don't double-close;
    // fclose(3) will close the underlying file descriptor,
    // and so will destroy_client()]
    if ((stream = fdopen(dup(client->fd), "r+"))== NULL) {
        perror("unable to wrap socket");
        goto cleanup;
    } else {

	}

    int http_result = parseHttp(stream, &request);

    if (http_result == 1) {
        fprintf(stream,"HTTP/1.0 200 OK\n");
        fprintf(stream,"Content-type: text/plain\n");
        fprintf(stream, "\r\n");
        fprintf(stream, "Request verb: %s\n", request->verb);
        fprintf(stream, "Requested file: %s%s\n", g_settings.directory, request->path);
    } else {
        fprintf(stream, "HTTP/1.0 400 Bad Request\n");
        fprintf(stream, "Content-type: text/plain\n");
        fprintf(stream, "\r\n");
        fprintf(stream, "I did not understand your request\n");
    }
    free(request->verb);
    free(request->path);
    free(request->version);
    free(request);  // It's OK to free() a NULL pointer

cleanup:
    // Shutdown this client
    if (stream) fclose(stream);
    destroy_client_info(client);
    printf("\tSession ended.\n");
}

// Opens the directory specified in the server start up. TODO: Reimplement for full release.
// DIR* open_specified_directory(const char *dir) {
    /*DIR *open_result = opendir(dir);
    if (open_result == NULL) {
        printf("error opening specified directory.\n");
        if (errno == ENONET) {
            printf("The specified directory does not exist.");
        } else if (errno == ENOTDIR) {
            printf("%s is not a directory.", dir);
        }
        printf("Opening default directory...");
        opendir("/home");
    }
    return open_result;
}*/

int main(int argc, char **argv) {
    int ret = 1;

    // Network server/client context
    int server_sock = -1;

    DIR *open_directory = NULL;

    // Handle our options
    if (parse_options(argc, argv)) {
        printf("usage: %s [-p PORT] [-r DIRECTORY] [-h HOSTNAME/IP]\n", argv[0]);
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
    // open_directory = open_specified_directory(g_settings.directory);

    if (server_sock < 0) {
        perror("unable to create socket");
        goto cleanup;
    }
    blog("Bound and listening on %s:%s\nOpen directory: %s", g_settings.bindhost, g_settings.bindport, g_settings.directory);

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
            handle_client(&client); // Client gets cleaned up in here
        }
    }
    ret = 0;

cleanup:
   // closedir(open_directory);
    if (server_sock >= 0) close(server_sock);
    return ret;
}

