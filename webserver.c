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
#include "utils.h"
#include "hash.h"

#define RC_OK 1
#define RC_ILLEGAL_STREAM -1
#define RC_IO_ERROR -2
#define RC_MALLOC_FAILURE -3
#define RC_ILLEGAL_VERB -4
#define RC_ILLEGAL_PATH -5
#define RC_MISSING_VERSION -6
#define RC_OTHER_ERR -7

#define FILE_NOT_FOUND -1
#define OTHER_ERROR -2

Hash_table* dict;

static char* keys[] = {".gif", ".jpg", ".jpeg", ".png", ".css", ".txt"};
static char* values[] = {"image/gif", "image/jpeg", "image/jpeg", "image/png", "text/css", "text/plain"};

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

void init_hash_table(Hash_table **table) {
    for (int i = 0; i < 6; i++) {
        ht_insert(*table, keys[i], values[i]);
    }
}

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
    int BUFFER_SIZE = 400;
    int STR_BUFFER = 500;
    char *line = malloc(1);
    char* result = NULL;
    int cur_len = 0;

    char illegalChars[] = "\"\\\\~\\\"`!@#$%^&*()-=+[{]}|;:'<>?,\"";

    char *buffer = malloc(BUFFER_SIZE);
    char *info_ptr;

    while ((result = fgets(buffer, sizeof(buffer), in)) != NULL) {
        size_t buffer_len = strlen(buffer);
        char *extra = realloc(line, buffer_len + 1 + cur_len);

        if (extra == 0) {
            break;
        }

        line = extra;
        strlcpy(line + cur_len, buffer, buffer_len + 1);
        cur_len += buffer_len;

        if (strcmp(result, "\r\n") == 0) {
            break;
        }
    }

    if (result == NULL) {
        rc = RC_IO_ERROR;
        blog("No newline found in request");
        goto cleanup;
    }

    if (strchr(line, ' ') == NULL) {
        RC_IO_ERROR;
        blog("Illegal request, no spaces within request");
        goto cleanup;
    }

    if ((req = calloc(10, sizeof(http_request_t))) == NULL) {
        rc = RC_MALLOC_FAILURE;
        blog("Calloc failure");
    }

    req -> verb = malloc(STR_BUFFER);
    req -> path = malloc(STR_BUFFER);
    req -> version = malloc(STR_BUFFER);

    strlcpy(req -> verb, (strtok_r(line, " ", &info_ptr)), STR_BUFFER); // assigning value to verb from the struct
    if (strcmp(req -> verb, "GET") == 0) {
    } else {
        rc = RC_ILLEGAL_VERB;
        blog("Illegal verb provided: %s", req -> verb);
        free_request(req);
        goto cleanup;
    }

    strlcpy(req -> path, (strtok_r(NULL, " ", &info_ptr)), STR_BUFFER); // assigning value to path from the struct
    if (strpbrk(req -> path, illegalChars)) {
        rc = RC_ILLEGAL_PATH;
        blog("Illegal path provided: %s", req -> path);
        free_request(req);
        goto cleanup;
    }

    strlcpy(req -> version, (strtok_r(NULL, " ", &info_ptr)), STR_BUFFER); // strtok_r requires using NULL after first call
    if (req -> version == NULL) {
        rc = RC_MISSING_VERSION;
        blog("Missing version");
        free_request(req);
        goto cleanup;
    }

    if (feof(in)) {
        rc = RC_ILLEGAL_STREAM;
    }

    if (ferror(in)) {
        rc = RC_IO_ERROR;
    }

    rc = RC_OK;
    *request = req;

cleanup:
    free(line);
    free(buffer);
    return rc;
}

// Print the default HTTP response if no file is specified
void print_http_ok(FILE *stream, http_request_t *request) {
    fprintf(stream,"HTTP/1.0 200 OK\n");
    fprintf(stream,"Content-type: text/plain\n");
    fprintf(stream, "\r\n");
    fprintf(stream, "Welcome to my server.\n");
    fprintf(stream, "Request verb: %s\n", request->verb);
    fprintf(stream, "Requested file: %s%s\n", g_settings.directory, request->path);
}

// prints out the HTTP response to the client if the file exists and the request is valid
void print_http_ok_with_file(FILE *stream, FILE *opened_file, char *extension)
{
    char *buffer = NULL;
    if ((buffer = malloc(1024)) == NULL) {
        blog("malloc failed");
        goto cleanup;
    }
    fprintf(stream, "HTTP/1.0 200 OK\n");
    fprintf(stream, "Content-type: %s\n", extension);
    fprintf(stream, "\r\n");
    while (feof(opened_file) == 0) {
        unsigned long long chunk_read = fread(buffer, 1, 400, opened_file);
        fwrite(buffer, 1, chunk_read, stream);
    }

cleanup:
    free(buffer);
    if (opened_file != NULL) {
        fclose(opened_file);
    }
}

// prints out the HTTP response to the client if the file does not exist or the request is invalid
void print_http_failure(FILE *stream, int error_type, char *extension)
{
    if (error_type == FILE_NOT_FOUND) {
        fprintf(stream, "HTTP/1.0 404 Not Found\n");
        fprintf(stream, "Content-type: %s\n", extension);
        fprintf(stream, "\r\n");
        fprintf(stream, "Error 404: Specified file not found and could not be open.\n");

    } else {
        fprintf(stream, "HTTP/1.0 400 Bad Request\n");
        fprintf(stream, "Content-type: %s\n", extension);
        fprintf(stream, "\r\n");
        fprintf(stream, "I did not understand your request\n");
    }
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
    if ((stream = fdopen(dup(client->fd), "r+"))== NULL) {
        perror("unable to wrap socket");
        goto cleanup;
    } else {}

    http_result = parseHttp(stream, &request);
    if (http_result != RC_OK) {
        print_http_failure(stream, OTHER_ERROR, NULL);
        goto cleanup;
    }

    if (strcmp(request->path, "/") == 0) {
        print_http_ok(stream, request);
        free_request(request);
        goto cleanup;
    }

    extension = strchr(request->path, '.');
    content_type = get_content_type(extension);

    // Concatenate the directory and the path to file
    file = malloc(strlen(g_settings.directory) + strlen(request->path) + 1);
    strlcpy(file, g_settings.directory, strlen(g_settings.directory) + 1);
    strlcat(file, request->path, strlen(g_settings.directory) + strlen(request->path) + 1);

    // Open the file specified in the request
    opened_file = fopen(file, "r");

    if (opened_file == NULL && strcmp(request->path, "/") != 0) {
        print_http_failure(stream, FILE_NOT_FOUND, content_type);
    } else {
        print_http_ok_with_file(stream, opened_file, content_type);
    }

    free_request(request);
    free(file);

cleanup:

    // Shutdown this client
    if (stream) fclose(stream);
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
    if (server_sock >= 0) close(server_sock);
    free_table(dict);
    return ret;
}

