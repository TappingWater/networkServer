/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <jwt.h>
#include <stdlib.h>
#include <jansson.h>
#include <pthread.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

char * server_root;     // root from which static files are served


/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)       // error, EOF, or less than 2 characters
        return false;
    
    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CRLF, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        char *field_value = strtok_r(NULL, " \t", &endptr);    // skip leading & trailing OWS

        if (field_name == NULL)
            return false;

        //printf("Header: %s: %s\n", field_name, field_value);
        if (!strcasecmp(field_name, "Content-Length")) 
        {
            ta->req_content_len = atoi(field_value);
        }

        if (!strcasecmp(field_name, "Cookie")) 
        {
            char *endptr;
            strtok_r(field_value, "=", &endptr);
            char *cookieValue = strtok_r(NULL, " \t", &endptr); 
            ta->cookieHeader = cookieValue;
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction * ta, buffer_t *res)
{
    if (ta->req_version == HTTP_1_0) {
        buffer_appends(res, "HTTP/1.0 ");
    }
    else {
        buffer_appends(res, "HTTP/1.1 ");    
    }

    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
        return false;

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found", 
        bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    if (!strcasecmp(suffix, ".css"))
        return "text/css";

    return "text/plain";
}

/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    
    //Handle indirect object reference
    char *root_path = realpath(server_root, NULL);
    if (root_path == NULL) {
        return send_error(ta, HTTP_NOT_FOUND, "Invalid URL.\n");
    }    
    strcat(root_path, req_path);    
    char *abs_path = realpath(root_path, NULL);
    if (abs_path == NULL) {
        return send_error(ta, HTTP_NOT_FOUND, "Invalid URL.\n");      
    }
    //If the absolute path of the requested file is not in the root directory
    //We want to deny permission here and send an error message
    if (strstr(abs_path, root_path) == NULL) {
        return send_error(ta, HTTP_NOT_FOUND, "Invalid URL.\n");             
    }

    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
            return send_not_found(ta);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    add_content_length(&ta->resp_headers, st.st_size);
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    success = bufio_sendfile(ta->client->bufio, filefd, NULL, st.st_size) == st.st_size;
out:
    close(filefd);
    return success;
}

static int
handle_api(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "API not implemented");
}

/**
 * Helper function used to handle a login request
 * The username and password for the server are hardcoded
 * username: user0
 * password: thepassword
 * If authenticated returns:
 *  Claim as JSON body containing: exp (token epiration), iat (token issue time), sub (username)
 *  ex: {"exp":1523737086,"iat":1523650686,"sub":"user0"}
 *  JSON web token 
 * Else returns:
 *  403 Forbidden
 **/
static bool handle_login(struct http_transaction *ta) 
{    
    static const char * KEY_DATA = "auth_Key";
    if (ta->req_method == HTTP_GET) 
    {
        ta->resp_status = HTTP_OK;
        jwt_t *ymtoken;
        //If there is no cookie header return NULL        
        if(ta->cookieHeader == NULL)
        {
            buffer_appends(&ta->resp_body, "{}\n");
            return send_response(ta);
        }
        //If JWT_decode creates an error
        if (jwt_decode(&ymtoken, ta->cookieHeader, (unsigned char *)KEY_DATA, strlen(KEY_DATA)) != 0)
        {
            buffer_appends(&ta->resp_body, "{}\n");
            return send_response(ta);            
        }
        //IF grant is NULL       
        char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
        if (grants == NULL)
        {
            buffer_appends(&ta->resp_body, "{}\n");
            return send_response(ta);            
        }
        //Check whether the expiration is valid
        time_t now = time(NULL);
        int exp = jwt_get_grant_int(ymtoken, "exp");
        if (exp != 0) {
            buffer_appends(&ta->resp_body, "{}\n");
            return send_response(ta);     
        }
        //If the current time is greater than the expiration time                
        if(now > exp)
        {
           buffer_appends(&ta->resp_body, "{}\n");
        }
        else
        {
            buffer_appends(&ta->resp_body, grants);
            buffer_appends(&ta->resp_body, "\n");
        }
        return send_response(ta);
    }
    else if (ta->req_method == HTTP_POST) 
    {
        //printf("Post\n");
        //Read the body of request
        ta->resp_status = HTTP_OK;
        char *body = bufio_offset2ptr(ta->client->bufio, ta->req_body);
        json_error_t error;
        json_t *loginInfo = json_loadb(body, ta->req_content_len, 0, &error);
        if (loginInfo == NULL) {
            return send_error(ta, HTTP_PERMISSION_DENIED, "Forbidden");        
        }
        json_t *userKey = json_object_get(loginInfo, "username");
        if (userKey == NULL) {
            return send_error(ta, HTTP_PERMISSION_DENIED, "Forbidden");
        }        
        json_t *passKey = json_object_get(loginInfo, "password");
        if (passKey == NULL) {
            return send_error(ta, HTTP_PERMISSION_DENIED, "Forbidden");
        }
        const char *userName = json_string_value(userKey);
        const char *password = json_string_value(passKey);
        
        //If the username and password given in the body are correct
        if (strcmp(userName, "user0") == 0 && strcmp(password, "thepassword") == 0) 
        {
            printf("authenticated\n");
            ta->resp_status = HTTP_OK;
            jwt_t *clientClaim;
            //send the claim to the client
            if (jwt_new(&clientClaim))
                perror("jwt_new"), exit(-1);
            if (jwt_add_grant(clientClaim, "sub", "user0"))
                perror("jwt_add_grant sub"), exit(-1);
            time_t now = time(NULL);
            if (jwt_add_grant_int(clientClaim, "iat", now))
                perror("jwt_add_grant iat"), exit(-1);
            if (jwt_add_grant_int(clientClaim, "exp", now + 3600 * 24))
                perror("jwt_add_grant exp"), exit(-1);

            //return a cookie to give token autentication to client
            if (jwt_set_alg(clientClaim, JWT_ALG_HS256, (unsigned char *)KEY_DATA , strlen(KEY_DATA)))
                perror("jwt_set_alg"), exit(-1);
            
            char *authorizationToken = jwt_encode_str(clientClaim);
            //printf("%s\n", authorizationToken);
            if (authorizationToken == NULL)
                perror("jwt_encode_str"), exit(-1);
            char totalToken[500];
            char *tokenName = "auth_token=";
            char *tokenPath = "; Path=/";
            strcpy(totalToken, tokenName);
            strcat(totalToken, authorizationToken);
            strcat(totalToken, tokenPath);
            http_add_header(&ta->resp_headers, "Set-Cookie", totalToken);
            
            //return the body of the claim
            jwt_t *bodyClaim;
            if (jwt_decode(&bodyClaim, authorizationToken, (unsigned char *)KEY_DATA, strlen(KEY_DATA)))
                perror("jwt_decode"), exit(-1);
            
            char *bodyResponse = jwt_get_grants_json(bodyClaim, NULL); // NULL means all
            if (bodyResponse == NULL)
                perror("jwt_get_grants_json"), exit(-1);
            buffer_appends(&ta->resp_body, bodyResponse);
            buffer_appends(&ta->resp_body, "\n");
            return send_response(ta);
        }
        //If user cannot be authenticated
        else 
        {
            //return a 403 forbidden
            return send_error(ta, HTTP_PERMISSION_DENIED, "Forbidden");
        }
        //return true;
    }
    else 
    {
        return send_error(ta, HTTP_METHOD_NOT_ALLOWED, "Unknown method: This server only supports GET and POST requests");     
    }
}

static bool handle_private(struct http_transaction *ta, char *basedir)
{
    bool isValidated = handle_login(ta);
    bool accessedPrivateFile = handle_static_asset(ta, basedir);
    if(isValidated && accessedPrivateFile)
    {
        return true;
    }
    else
    {
        return send_error(ta, HTTP_PERMISSION_DENIED, "Forbidden");
    }
}

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
void *
http_handle_transaction(void * client)
{

    struct http_client *self = malloc(sizeof(struct http_client));
    self = client; 
    bool keepAlive = true;
    while(keepAlive)
    {
        struct http_transaction ta;
        memset(&ta, 0, sizeof ta);
        ta.client = self;
        if (!http_parse_request(&ta))
            break;

        if (!http_process_headers(&ta))
            break;

        if (ta.req_content_len > 0) {
            int body_len = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
            if (body_len != ta.req_content_len)
                break;
        }

        buffer_init(&ta.resp_headers, 1024);
        http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
        
        buffer_init(&ta.resp_body, 0);
        
        keepAlive = false;
        char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
        if (STARTS_WITH(req_path, "/api")) {
            if (STARTS_WITH(req_path, "/api/login")) {   
                printf("api login\n");         
                keepAlive = handle_login(&ta);                
            }
            else {
                keepAlive = handle_api(&ta);
            }
        }
        else if (STARTS_WITH(req_path, "/private")) {
            /* not implemented, need to request a token */
            keepAlive = handle_private(&ta, server_root);
        }
        else {
            keepAlive = handle_static_asset(&ta, server_root);
        }

        buffer_delete(&ta.resp_headers);
        buffer_delete(&ta.resp_body);
        if (ta.req_version == HTTP_1_1 && keepAlive) 
        { 
            bufio_truncate(self->bufio);
            keepAlive = true;
        }
        else 
        {
            keepAlive = false;
        }
    }
    bufio_close(self->bufio);    
    return NULL;
}
