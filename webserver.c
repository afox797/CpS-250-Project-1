/* Echo Server: an example usage of EzNet
 * (c) 2016, Bob Jones University
 */
#include <stdbool.h>    // For access to C99 "bool" type
#include <stdio.h>      // Standard I/O functions
#include <stdlib.h>     // Other standard library functions
#include <string.h>     // Standard string functions
#include <errno.h>      // Global errno variable
#include <bsd/string.h> // Safe string functions

#include <unistd.h>     // Standard system calls
#include <signal.h>     // Signal handling system calls (sigaction(2))

#include "eznet.h"      // Custom networking library
#include "utils.h"      // Custom utility functions
#include "hash.h"       // Custom hash table functions from https://www.journaldev.com/35238/hash-table-in-c-plus-plus#:~:text=A%20Hash%20Table%20in%20C,value%20at%20the%20appropriate%20location.

#define RC_NO_FILE 2
#define RC_OK 1
#define RC_ILLEGAL_STREAM -1
#define RC_IO_ERROR -2
#define RC_MALLOC_FAILURE -3
#define RC_ILLEGAL_VERB -4
#define RC_ILLEGAL_PATH -5
#define RC_MISSING_VERSION -6
#define RC_OTHER_ERR -7
#define RC_NO_NEWLINE -8


#define FILE_NOT_FOUND -1
#define OTHER_ERROR -2

#define STR_BUFFER 150

// Global variables
Hash_table *dict;

static char *keys[] = {".gif", ".jpg", ".jpeg", ".png", ".css", ".txt"};
static char *values[] = {"image/gif", "image/jpeg", "image/jpeg", "image/png", "text/css", "text/plain"};

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

// Fills hash table with predefined keys and values.
void init_hash_table(Hash_table **table) {
    for (int i = 0; i < 6; i++) {
        ht_insert(*table, keys[i], values[i]);
    }
}

// Parse commandline options and sets g_settings accordingly.
// Returns 0 on success, -1 on false...
int parse_options(int argc, char *const argv[]) {
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
            case 'r':
                g_settings.directory = optarg;
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

void free_request(http_request_t *request) {
    if (request != NULL) {
        free(request->verb);
        free(request->path);
        free(request->version);
        free(request);
    }
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

    char *buffer = malloc(BUFFER_SIZE);
    char *info_ptr;

    fgets(buffer, BUFFER_SIZE, in);


    if (strlen(buffer) > BUFFER_SIZE - 5) {
        blog("Client attempted to create buffer overflow, sending back HTTP 400");
        rc = RC_ILLEGAL_STREAM;
        goto cleanup;
    }

    if (buffer[strlen(buffer) - 1] != '\n' && buffer[strlen(buffer) - 2] != '\r') {
        blog("Invalid HTTP request: missing newline character. Terminating connection.");
        goto leave;
    }

    int count = 0;
    for (int i = 0; i < strlen(buffer); i++) {
        if (strchr(" ", buffer[i]) != NULL) {
            count++;
        }
    }

    if (count != 2) {
        blog("Malformed HTTP request, missing some required component of the request. Sending back HTTP 400");
        rc = RC_ILLEGAL_STREAM;
        goto cleanup;
    }

    if ((req = calloc(10, sizeof(http_request_t))) == NULL) {
        rc = RC_MALLOC_FAILURE;
    }

    req -> verb = malloc(STR_BUFFER);
    req -> path = malloc(STR_BUFFER);
    req -> version = malloc(STR_BUFFER);

    strlcpy(req -> verb, (strtok_r(buffer, " ", &info_ptr)), STR_BUFFER); // assigning value to verb from the struct
    strlcpy(req -> path, (strtok_r(NULL, " ", &info_ptr)), STR_BUFFER); // strtok_r requires using NULL after first call
    strlcpy(req -> version, (strtok_r(NULL, " ", &info_ptr)), STR_BUFFER); // strtok_r requires using NULL after first call

    if (strcmp(req -> verb, "GET") != 0) {
        rc = RC_ILLEGAL_VERB;
        free_request(req);
        goto cleanup;
    }

    if (strcmp(req->path, "/") == 0) {
        rc = RC_NO_FILE;
    }

    if (feof(in)) {
        rc = RC_ILLEGAL_STREAM;
    }

    if (ferror(in)) {
        rc = RC_IO_ERROR;
    }

    if (rc == RC_OTHER_ERR) {
        rc = RC_OK;
    }
    *request = req;

cleanup:
    while (strcmp((result = fgets(buffer, BUFFER_SIZE, in)), "\r\n") != 0) {
        if (ferror(in)) {
            rc = RC_IO_ERROR;
        }
        if (result == NULL) {
            rc = RC_ILLEGAL_STREAM;
            break;
        }
    }

    free(buffer);
    return rc;

leave:
    rc = RC_NO_NEWLINE;
    free(buffer);
    return rc;
}

// Gets the content type of the file based on the extension
char *get_content_type(char *extension) {
    char *type = NULL;
    type = ht_search(dict, extension);
    if (type == NULL) {
        return "application/octet-stream";
    } else {
        return type;
    }
}

// prints out the HTTP response to the client if the file exists and the request is valid
void print_http_ok(FILE *stream, FILE *opened_file, http_request_t *request, char *extension) {
    char *buffer = NULL;
    if ((buffer = malloc(1024)) == NULL) {
        blog("malloc failed");
        goto cleanup;
    }

    fprintf(stream, "HTTP/1.0 200 OK\n");
    fprintf(stream, "Content-type: %s\n", extension);
    fprintf(stream, "\r\n");

    if (opened_file == NULL) {
        fprintf(stream, "Requested file: %s%s \n", g_settings.directory ,request->path);
        fprintf(stream, "Welcome to my server.\n");
        fprintf(stream, "Request verb: %s\n", request->verb);
    } else {
        while (feof(opened_file) == 0) {
            unsigned long long chunk_read = fread(buffer, 1, 400, opened_file);
            fwrite(buffer, 1, chunk_read, stream);
        }
    }

    cleanup:
    free(buffer);
}

// prints out the HTTP response to the client if the file does not exist or the request is invalid
void print_http_failure(FILE *stream, int error_type, char *extension) {
    if (error_type == FILE_NOT_FOUND) {
        blog("File not found");
        fprintf(stream, "HTTP/1.0 404 Not Found\n");
        fprintf(stream, "Content-type: %s\n", get_content_type(extension));
        fprintf(stream, "\r\n");
        fprintf(stream, "Error 404: Specified file not found and could not be open.\n");

    } else {
        fprintf(stream, "HTTP/1.0 400 Bad Request\n");
        fprintf(stream, "Content-type: %s\n", get_content_type(extension));
        fprintf(stream, "\r\n");
        fprintf(stream, "I did not understand your request\n");
    }
}

// Connection handling logic: reads/echos lines of text until error/EOF,
// then tears down connection.
void handle_client(struct client_info *client) {
    FILE *stream = NULL;
    FILE *opened_file = NULL;
    http_request_t *request = NULL;
    char *content_type = NULL;
    char *extension = NULL;
    char *file = NULL;
    int http_result;
    // Wrap the socket file descriptor in a read/write FILE stream
    // so we can use tasty stdio functions like getline(3)
    // [dup(2) the file descriptor so that we don't double-close;
    // fclose(3) will close the underlying file descriptor,
    // and so will destroy_client()]
    if ((stream = fdopen(dup(client->fd), "r+")) == NULL) {
        perror("unable to wrap socket");
        goto cleanup;
    } else {}

    http_result = parseHttp(stream, &request);

    if (http_result == RC_NO_NEWLINE) {
        goto cleanup;
    }

    // Concatenate the directory and the path to file
    if (http_result == RC_OK || http_result == RC_NO_FILE) {
        file = malloc(strlen(g_settings.directory) + strlen(request->path) + 1);
        strlcpy(file, g_settings.directory, strlen(g_settings.directory) + 1);
        strlcat(file, request->path, strlen(g_settings.directory) + strlen(request->path) + 1);

        // Open the file specified in the request
        opened_file = fopen(file, "r");

        if (opened_file == NULL && http_result != RC_NO_FILE) {
            http_result = FILE_NOT_FOUND;
        }

        extension = strchr(request->path, '.');
        content_type = get_content_type(extension);

    } else {
        print_http_failure(stream, OTHER_ERROR, content_type);
        goto cleanup;
    }

    if (http_result == FILE_NOT_FOUND) {
        print_http_failure(stream, FILE_NOT_FOUND, content_type);
    } else if (http_result == 2) {
        print_http_ok(stream, NULL, request, content_type);
    } else {
        print_http_ok(stream, opened_file, request, content_type);
    }

    free_request(request);
    free(file);

    cleanup:
    if (opened_file != NULL) {
        fclose(opened_file);
    }

    if (stream != NULL) {
        fclose(stream);
    }
    // Shutdown this client
    destroy_client_info(client);
    printf("\tSession ended.\n");
}

int main(int argc, char **argv) {
    int ret = 1;

    // Network server/client context
    int server_sock = -1;

    // Initialize the hash table\dictionary
    dict = create_table(CAPACITY);
    init_hash_table(&dict);

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
    blog("Bound and listening on %s:%s\nOpen directory: %s", g_settings.bindhost, g_settings.bindport,
         g_settings.directory);

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
    if (server_sock >= 0) close(server_sock);
    free_table(dict);
    return ret;
}

