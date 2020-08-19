#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include <libxml/xmlmemory.h>
#include <libxml/xpath.h>
#include <libxml/parser.h>

#include "storage.h"
#include "common.h"
#include "log.h"
#include "serializer.h"
#include "xapi.h"

#define XAPI_CONNECT_RETRIES 5
#define XAPI_CONNECT_SLEEP 3

#define MAX_RESPONSE_SIZE 4096
#define MAX_RESUME_FILE_SIZE (8*PAGE_SIZE)

#define VM_UUID_MAX 36

static char VM_UUID[VM_UUID_MAX];

static bool xapi_uuid_initialized = false;

extern char root_path[PATH_MAX];
char socket_path[108];

static bool socket_path_initialized = false;

/* The maximum number of digits in the Content-Length HTTP field */
#define MAX_CONTENT_LENGTH_DIGITS 16

#define HTTP_HEADER                                                            \
    "POST / HTTP/1.1\r\n"                                                      \
    "Host: _var_lib_xcp_xapi\r\n"                                              \
    "Accept-Encoding: identity\r\n"                                            \
    "User-Agent: uefistored/0.1\r\n"                                            \
    "Connection: close\r\n"                                                    \
    "Content-Type: text/xml\r\n"                                               \
    "Content-Length: %lu\r\n"                                                  \
    "\r\n"

#define HTTP_BODY_SET_NVRAM_VARS                                               \
    "<?xml version='1.0'?>"                                                    \
    "<methodCall>"                                                             \
    "<methodName>VM.set_NVRAM_EFI_variables</methodName>"                      \
    "<params>"                                                                 \
    "<param><value><string>DUMMYSESSION</string></value></param>"              \
    "<param><value><string>DUMMYVM</string></value></param>"                   \
    "<param><value><string>%s</string></value></param>"                        \
    "</params>"                                                                \
    "</methodCall>"

#define SOCKET_MAX 108

static char *xapi_save_path;
static char *xapi_resume_path;

char socket_path[SOCKET_MAX];

int xapi_parse_arg(char *arg)
{
    char *p;

    /* TODO: no longer use strncpy, just point a pointer */
    if ((p = strstr(optarg, "socket:")) != NULL) {
        p += sizeof("socket:") - 1;
        strncpy(socket_path, p, SOCKET_MAX);
        socket_path_initialized = true;

        return 0;

    } else if ((p = strstr(optarg, "uuid:")) != NULL) {
        p += sizeof("uuid:") - 1;
        strncpy(VM_UUID, p, VM_UUID_MAX);
        xapi_uuid_initialized = true;

        return 0;
    } else if ((p = strstr(optarg, "save:")) != NULL) {
        p += sizeof("save:") - 1;
        xapi_save_path = p;

        return 0;
    } else if ((p = strstr(optarg, "resume:")) != NULL) {
        p += sizeof("resume:") - 1;
        xapi_resume_path = p;

        return 0;
    }


    return 0;
}

/**
 * This function populates an array of variables from byte-serialized form.
 *
 * @parm vars the buffer array of variables
 * @parm n the max size of the array
 * @parm bytes pointer to the array of bytes of serialized variables
 * @parm bytes_sz the size of the array of bytes
 *
 * @return the number of variables on success, otherwise -1.
 */
int from_bytes_to_vars(variable_t *vars, size_t n, const uint8_t *bytes, size_t bytes_sz)
{
    int ret;
    const uint8_t *ptr = bytes;
    struct variable_list_header hdr;
    int i;

    if (!ptr)
        return -1;

    unserialize_variable_list_header(&ptr, &hdr);

    if (hdr.variable_count > n)
        return -1;

    for (i = 0; i < hdr.variable_count; i++) {
        ret = unserialize_var_cached(&ptr, &vars[i]);

        if (ret < 0)
            break;
    }

    return i;
}

/**
 * This function reads variables from a file into an array of variables.
 *
 * @parm vars an array of variables
 * @parm n the number of variables in the array
 * @parm fname the name of the file
 *
 * @return the number of variables stored in vars.
 */
int xapi_variables_read_file(variable_t *vars, size_t n, char *fname)
{
    int fd;
    FILE *file = NULL;
    uint8_t *mem;
    ssize_t size;
    int ret;
    struct stat stat;

    if ( !fname || !vars )
        return -1;

    file = fopen(fname, "r");

    if ( !file )
        return -1;

    fd = fileno(file);

    ret = fstat(fd, &stat);

    if ( ret < 0 )
        goto cleanup1;

    if ( stat.st_size > MAX_RESUME_FILE_SIZE )
    {
        ret = -1;
        goto cleanup1;
    }

    mem = malloc(stat.st_size);

    if ( !mem )
    {
        ret = -1;
        goto cleanup1;
    }

    size = fread(mem, 1, stat.st_size, file);

    if ( size != stat.st_size )
    {
        ret = -1;
        goto cleanup2;
    }

    ret = from_bytes_to_vars(vars, n, mem, size);

cleanup2:
    free(mem);

cleanup1:
    fclose(file);

    return ret;
}


/**
 * Return the HTTP Status from a an HTTP response.
 *
 * @message: str
 *      The HTTP response, must be null-terminated.
 */
static int http_status(char *response)
{
    char *p;
    long status;

    if (!response)
        return -1;

    p = strchr(response, ' ');

    if (!p) {
        ERROR("Invalid HTTP in response\n");
        return -1;
    }

    status = strtol(p, NULL, 10);

    if (status == LONG_MIN || status == LONG_MAX || status > INT_MAX) {
        ERROR("Bad http status: %lu\n", status);
        return -1;
    }

    return (int)status;
}

static char *response_body(char *response)
{
    char *body;

    if (!response)
        return NULL;

    body = strstr(response, "\r\n\r\n");

    if (!body)
        return NULL;

    return body + 4;
}

int base64_to_bytes(uint8_t *plaintext, size_t n, char *encoded,
                   size_t encoded_size)
{
    size_t ret;

    if (!plaintext || n == 0 || !encoded || encoded_size == 0)
        return -1;

    BIO *mem, *b64;

    b64 = BIO_new(BIO_f_base64());
    mem = BIO_new_mem_buf(encoded, encoded_size);

    mem = BIO_push(b64, mem);

    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(mem, BIO_CLOSE);

    ret = BIO_read(mem, plaintext, encoded_size);

    BIO_free_all(mem);

    if (ret == 0) {
        ERROR("No data decrypted!\n");
        return -1;
    }

    return ret > INT_MAX ? -2 : (int)ret;
}

char *bytes_to_base64(uint8_t *buffer, size_t length)
{
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *bufferPtr = NULL;
    char *b64text = NULL;

    if (length <= 0)
        goto cleanup;

    b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL)
        goto cleanup;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        goto cleanup;

    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(bio, BIO_CLOSE);

    if (BIO_write(bio, (char *)buffer, (int)length) <= 0)
        goto cleanup;

    if (BIO_flush(bio) != 1)
        goto cleanup;

    BIO_get_mem_ptr(bio, &bufferPtr);

    b64text = (char *)malloc((bufferPtr->length + 1) * sizeof(char));
    if (b64text == NULL)
        goto cleanup;

    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';
    BIO_set_close(bio, BIO_NOCLOSE);

cleanup:
    BIO_free_all(bio);
    BUF_MEM_free(bufferPtr);

    return b64text;
}

#define OFFSET_SZ 4

size_t list_size(variable_t *variables, size_t n)
{
    size_t i, sz;

    sz = sizeof(struct variable_list_header);

    for (i = 0; i < n; i++)
        sz += variable_size(&variables[i]) + VAR_PADDING;

    return sz;
}

/**
 * Retrieves variables from db and stores in vars arg
 *
 * Returns the count of variables retrieved.
 */
static int retrieve_vars(variable_t *vars, size_t n)
{
    int ret;
    size_t cnt = 0;
    variable_t *next;

    memset(vars, 0, sizeof(*vars) * n);

    next = &vars[0];

    while (cnt < n) {
        ret = storage_next(next);

        /* Error */
        if (ret < 0)
            return ret;

        /* Last variable */
        if (ret == 0)
            break;

        next++;
        cnt++;
    }

    /* Too many variables */
    if (cnt > INT_MAX)
        return -1;

    return cnt;
}

/**
 * Return all variables in storage as a list of bytes, in legacy varstore
 * format with header.
 *
 * Parameters
 * 
 *  size: the size of the returned byte array
 */
static uint8_t *variable_list_bytes(size_t *size)
{
    int ret;
    uint8_t *bytes, *p;
    variable_t vars[MAX_VAR_COUNT];

    ret = retrieve_vars(vars, MAX_VAR_COUNT);

    if (ret <= 0)
        return NULL;

    *size = list_size(vars, ret);
    bytes = malloc(*size);

    if (!bytes)
        return NULL;

    p = bytes;
    ret = serialize_variable_list(&p, *size, vars, (size_t)ret);

    if ( ret < 0 )
    {
        free(bytes);
        return NULL;
    }

    return bytes;
}

/**
 * Return all stored variables in legacy varstore format
 * as a base64 string.
 */
static char *variable_list_base64(void)
{
    char* base64;
    uint8_t *bytes;
    size_t size;

    bytes = variable_list_bytes(&size);

    if (!bytes)
        return NULL;

    base64 = bytes_to_base64(bytes, size);

    free(bytes);

    return base64;
}

static int create_header(size_t body_len, char *message, size_t message_size)
{
    int ret;

    ret = snprintf(message, message_size, HTTP_HEADER, body_len);

    if (ret < 0) {
        return ret;
    }

    return ret;
}

static int build_set_efi_vars_message(char *buffer, size_t n)
{
    int ret;
    char *base64;
    char *body;
    size_t base64_size, body_len, hdr_len;

    base64 = variable_list_base64();
    if (!base64)
        return -1;

    base64_size = strlen(base64);
    body_len = sizeof(HTTP_BODY_SET_NVRAM_VARS) + base64_size - 1;

    body = malloc(body_len);

    if (!body) {
        free(base64);
        return -1;
    }

    ret = snprintf(body, body_len, HTTP_BODY_SET_NVRAM_VARS, base64);

    if (ret < 0) {
        ret = -1;
        goto end;
    }

    body_len = strlen(body);

    hdr_len = create_header(body_len, buffer, n);
    if (hdr_len < 0) {
        ret = -1;
        goto end;
    }

    strncpy(buffer + hdr_len, body, body_len);
    buffer[body_len + hdr_len] = '\0';

    ret = 0;
end:
    free(body);
    free(base64);

    return ret;
}

static int send_request(char *message, char *buf, size_t bufsz)
{
    int ret, fd;
    struct sockaddr_un saddr;

    saddr.sun_family = AF_UNIX;
    strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path));

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        ERROR("socket() failed: %d\n", fd);
        return fd;
    }

    ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));

    if (ret < 0) {
        close(fd);
        ERROR("connect() failed: %d, %s\n", errno, strerror(errno));
        return ret;
    }

    ret = write(fd, message, strlen(message));

    if (ret < 0) {
        close(fd);
        ERROR("write() failed: %d\n", ret);
        return ret;
    }

    ret = read(fd, buf, bufsz);

    if (ret < 0) {
        close(fd);
        ERROR("read() failed: %d\n", ret);
        return ret;
    }

    close(fd);
    buf[ret] = '\0';
    return http_status(buf);
}

/**
 * Save vars to XAPI database.
 *
 * Returns 0 on success, otherwise -1.
 */
int xapi_set_efi_vars(void)
{
    char buffer[BIG_MESSAGE_SIZE];
    int ret;

    ret = build_set_efi_vars_message(buffer, BIG_MESSAGE_SIZE);
    if (ret < 0)
        return ret;

    ret = send_request(buffer, buffer, BIG_MESSAGE_SIZE);

    return ret == 200 ? 0 : -1;
}

#define HTTP_LOGIN                                                             \
    "POST / HTTP/1.1\r\n"                                                      \
    "Host: _var_lib_xcp_xapi\r\n"                                              \
    "Accept-Encoding: identity\r\n"                                            \
    "User-Agent: uefistored/0.1\r\n"                                            \
    "Connection: close\r\n"                                                    \
    "Content-Type: text/xml\r\n"                                               \
    "Content-Length: 307\r\n"                                                  \
    "\r\n"                                                                     \
    "<?xml version='1.0'?>"                                                    \
    "<methodCall>"                                                             \
    "<methodName>session.login_with_password</methodName>"                     \
    "<params>"                                                                 \
    "<param><value><string>root</string></value></param>"                      \
    "<param><value><string></string></value></param>"                          \
    "<param><value><string></string></value></param>"                          \
    "<param><value><string></string></value></param>"                          \
    "</params>"                                                                \
    "</methodCall>"

int xapi_connect(void)
{
    char response[MAX_RESPONSE_SIZE];
    int retries = XAPI_CONNECT_RETRIES;
    int ret;

    while (retries-- > 0) {
        ret = send_request(HTTP_LOGIN, response, MAX_RESPONSE_SIZE);

        if (ret == 200)
            break;

        INFO("%s: retrying...\n", __func__);
        sleep(XAPI_CONNECT_SLEEP);
    }

    return ret;
}

int xapi_request(char *response, size_t response_sz, const char *format, ...)
{
    va_list ap;
    char message[BIG_MESSAGE_SIZE];
    char body[3 * 1024];
    int hdr_len;
    size_t body_len;
    int ret;

    va_start(ap, format);
    ret = vsnprintf(body, 3 * 1024, format, ap);
    va_end(ap);

    if (ret < 0)
        return ret;

    body_len = ret;

    hdr_len = create_header(body_len, message, BIG_MESSAGE_SIZE);

    if (hdr_len < 0) {
        return -1;
    }

    strncat(message, body, BIG_MESSAGE_SIZE);

    if (strlen(message) == (BIG_MESSAGE_SIZE - 1)) {
        WARNING("message length is exactly, equal to buffer length.  May have lost bytes!\n");
    }

    ret = send_request(message, response, response_sz);

    return ret;
}

/**
 * Return true if body contains "SUCCESS" element, otherwise return false.
 *
 * body: an XML string
 */
static bool success(char *xml)
{
    size_t len;
    int ret;

    xmlDoc *doc;
    xmlXPathObject *obj;
    xmlXPathContext *context;
    xmlChar *string;

    if (!xml)
        return false;

    len = strlen(xml);

    doc = xmlReadMemory(xml, len + 1, "noname.xml", 0, 0);

    if (!doc) {
        ERROR("xmlReadMemory() error\n");
        return false;
    }

    context = xmlXPathNewContext(doc);
    if (!context) {
        ERROR("xmlXPathNewContext() error\n");
        return false;
    }

    obj = xmlXPathEvalExpression(
            (xmlChar *)"/methodResponse/params/param/value/struct/member[1]/value",
            context);

    if (!obj) {
        ERROR("xmlXPathEvalExpression() error\n");
        xmlXPathFreeContext(context);
        return false;
    }

    string = xmlNodeGetContent(obj->nodesetval->nodeTab[0]->xmlChildrenNode);

    if (!string) {
        ERROR("xmlNodeGetContent() error\n");
        xmlXPathFreeContext(context);
        xmlXPathFreeObject(obj);
        return false;
    }

    ret = memcmp(string, "Success", 8);

    xmlXPathFreeContext(context);
    xmlXPathFreeObject(obj);
    xmlFree(string);

    return ret == 0;
}

static int get_value(char *body, char *dest, size_t n)
{
    xmlXPathContext *context;
    xmlDoc *doc;
    xmlXPathObject *obj;
    xmlChar *string;

    if (!body || !dest) {
        return -1;
    }

    doc = xmlReadMemory(body, strlen(body), "dummy.xml", 0, 0);

    if (!doc) {
        ERROR("%s: xmlReadMemory() error\n", __func__);
        return -1;
    }

    context = xmlXPathNewContext(doc);

    if (!context) {
        ERROR("%s: xmlXPathNewContext() error\n", __func__);
        xmlFree(doc);
        return -1;
    }

    obj = xmlXPathEvalExpression(
            (xmlChar *)"/methodResponse/params/param/value/struct/member[2]/value",
            context);

    if (!obj) {
        ERROR("%s: xmlXPathEvalExpression() error\n", __func__);
        xmlXPathFreeContext(context);
        xmlFreeDoc(doc);
        return -1;
    }

    string = xmlNodeGetContent((xmlNodePtr)obj->nodesetval->nodeTab[0]);
    strncpy(dest, (char *)string, n);

    xmlFree(string);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(context);
    xmlFreeDoc(doc);

    return 0;
}

int get_response_content(char *response, char *outstr, size_t n)

{
    char *body;

    if (!response) {
        ERROR("%s, response=(null)\n", response);
        return -1;
    }

    body = response_body(response);

    if (!success(body)) {
        return -2;
    }

    if (outstr && n > 0)
        return get_value(body, outstr, n);

    return 0;
}

/**
 * This function sends a VM.get_by_uuid request to XAPI.
 *
 * @parm session_id the currently open session id.
 *
 * @return 0 on success, -1 on failure.
 */
static int xapi_vm_get_by_uuid(char *session_id)
{
    int status, ret;
    char response[1024] = { 0 };

    status = xapi_request(response, 1024,
                          "<?xmlversion=\'1.0\'?>"
                          "<methodCall>"
                          "<methodName>VM.get_by_uuid</methodName>"
                          "<params>"
                          "<param><value><string>%s</string></value></param>"
                          "<param><value><string>%s</string></value></param>"
                          "</params>"
                          "</methodCall>",
                          session_id, vm_uuid);

    if (status != 200) {
        ERROR("Failed to communicate with XAPI\n");
        return -1;
    }

    if (!success(response_body(response))) {
        ERROR("failed to look up VM\n");
        DEBUG("body=%s\n", response_body(response));
        return -1;
    }

    return 0;
}

/**
 * This function sends a session.login_with_password request to XAPI.
 *
 * @parm session_id the buffer to store the session id.
 * @parm n the max size of buffer session_id.
 *
 * @return 0 on success, -1 on failure.
 */
int session_login(char *session_id, size_t n)
{
    int status, ret;
    char response[1024] = { 0 };

    status = xapi_request(response, 1024,
                          "<?xmlversion=\'1.0\'?>"
                          "<methodCall>"
                          "<methodName>session.login_with_password</methodName>"
                          "<params>"
                          "<param><value><string>root</string></value></param>"
                          "<param><value><string></string></value></param>"
                          "<param><value><string></string></value></param>"
                          "<param><value><string></string></value></param>"
                          "</params>"
                          "</methodCall>");

    if (status != 200) {
        ERROR("failed to login to xapi, status=%d\n", status);
        return -1;
    }

    ret = get_response_content(response, session_id, n);

    if (ret < 0) {
        ERROR("failed to login to xapi, ret=%d\n", ret);
        return -1;
    }

    return 0;
}

/**
 * This function sends a session.logout request to XAPI.
 *
 * @parm session_id the current session's id.
 *
 * @return 0 on success, -1 on failure.
 */
int session_logout(char *session_id)
{
    int status;
    char response[1024] = { 0 };

    status = xapi_request(response, 1024,
                          "<?xmlversion=\'1.0\'?>"
                          "<methodCall>"
                          "<methodName>session.logout</methodName>"
                          "<params>"
                          "<param><value><string>%s</string></value></param>"
                          "</params>"
                          "</methodCall>",
                          session_id);

    if (status != 200) {
        ERROR("failed to logout of xapi session\n");
        return -1;
    }

    if (!success(response_body(response))) {
        ERROR("failed to logout of xapi session\n");
        return -1;
    }

    return 0;
}

/**
 * This function returns the EFI vars in the VM.get_NVRAM XAPI XML response as Base64.
 *
 * @parm buffer the destination buffer
 * @parm n the max size of buffer
 * @parm body the null-terminated XML body
 *
 * @return 0 on succes, -1 on failure.
 */
int base64_from_response_body(char *buffer, size_t n, char *body)
{
    size_t len;
    xmlXPathObject *obj;
    xmlDoc *doc;
    xmlXPathContext *context;
    xmlChar *string;

    if (!body || !buffer)
        return -1;

    len = strlen(body);

    doc = xmlReadMemory(body, len + 1, "dummy.xml", NULL, 0);

    if (!doc) {
        ERROR("null doc! err=%d, errstring=%s\n", errno, strerror(errno));
        return -1;
    }

    context = xmlXPathNewContext(doc);

    if (!context) {
        free(doc);

        ERROR("xmlXPathNewContext() failed!\n");
        return -1;
    }

    obj = xmlXPathEvalExpression(
            (xmlChar *)"/methodResponse/params/param/value/struct/member[1]/value",
            context);

    if (!obj) {
        ERROR("xmlXPathEvalExpression() failed!\n");
        free(doc);
        xmlXPathFreeContext(context);

        return -1;
    }

    string = xmlNodeGetContent((xmlNodePtr)obj->nodesetval->nodeTab[0]);
    if (memcmp(string, "Success", 8) != 0) {
        INFO("xapi response, no success!\n");
        free(doc);
        xmlXPathFreeContext(context);
        xmlXPathFreeObject(obj);

        return -1;
    }

    xmlFree(string);
    xmlXPathFreeObject(obj);

    obj = xmlXPathEvalExpression(
            (xmlChar *)"/methodResponse/params/param/value/struct/member/value/struct/member[name=\"EFI-variables\"]/value",
            context);

    if (!obj || !obj->nodesetval) {
        free(doc);
        free(context);

        ERROR("EFI-vars not found in response\n");

        return -1;
    }

    string = xmlNodeGetContent(obj->nodesetval->nodeTab[0]);

    strncpy(buffer, (char *)string, n);

    xmlFree(string);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(context);
    xmlFreeDoc(doc);

    return 0;
}

int base64_from_response(char *buffer, size_t n, char *response)
{
    char *body;

    body = response_body(response);

    if (!body)
        return -1;

    return base64_from_response_body(buffer, n, body);
}

static int xapi_get_nvram(char *session_id, char *buffer, size_t n)
{
    int status;
    char response[BIG_MESSAGE_SIZE] = { 0 };

    status = xapi_request(response, BIG_MESSAGE_SIZE,
                          "<?xmlversion=\'1.0\'?>"
                          "<methodCall>"
                          "<methodName>VM.get_NVRAM</methodName>"
                          "<params>"
                          "<param><value><string>%s</string></value></param>"
                          "<param><value><string>%s</string></value></param>"
                          "</params>"
                          "</methodCall>",
                          session_id, VM_UUID);

    if (status != 200)
        return -1;

    return base64_from_response(buffer, n, response);
}

/**
 * This function stores the EFI vars locally after pulling them from XAPI.
 *
 * @parm vars the array of variables to store EFI vars into
 * @parm n the max size of the array vars
 *
 * @return number of variables stored.
 */
int xapi_variables_request(variable_t *vars, size_t n)

{
    int retries = 5;
    int ret;
    char session_id[512];
    uint8_t plaintext[BIG_MESSAGE_SIZE];
    char b64[BIG_MESSAGE_SIZE];

    ret = session_login(session_id, 512);

    while (ret < 0 && retries > 0) {
        usleep(100000);
        ret = session_login(session_id, 512);
        retries--;
    }

    if (ret < 0)
        return 0;

    ret = xapi_vm_get_by_uuid(session_id);

    if (ret < 0)
        return 0;

    ret = xapi_get_nvram(session_id, b64, BIG_MESSAGE_SIZE);

    if (ret < 0) {
        ERROR("failed to get NVRAM from xapi, ret=%d\n", ret);
        return 0;
    }

    ret = base64_to_bytes(plaintext, BIG_MESSAGE_SIZE, b64, strlen(b64));

    if (ret < 0)
        return 0;

    return from_bytes_to_vars(vars, n, plaintext, (size_t)ret);
}

/**
 * This function initializes the xapi module.
 *
 * @parm resume boolean representing if the VM is resuming.
 *
 * @return 0 on success, otherwise -1. 
 */
int xapi_init(bool resume)
{
    int i, ret, len;
    variable_t variables[MAX_VAR_COUNT];
    variable_t *var;

    memset(variables, 0, sizeof(variables));

    if (!xapi_uuid_initialized) {
        ERROR("No uuid initialized passed as arg!\n");
        return -1;
    }

    if (resume)
        ret = xapi_variables_read_file(variables, MAX_VAR_COUNT, xapi_resume_path);
    else
        ret = xapi_variables_request(variables, MAX_VAR_COUNT);

    if (ret < 0)
        return ret;

    len = ret;

    for (i=0; i<len; i++) {
        var = &variables[i];
        ret = storage_set(var->name, &var->guid, var->data, var->datasz, var->attrs);
        
        if ( ret < 0 )
        {
            ERROR("failed to set variable\n");
        }
    }

    return 0;
}

/**
 * Write variables with header to save file.
 *
 * Return 0 on success, otherwise -1.
 */
int xapi_write_save_file(void)
{
    int ret;
    FILE *file;
    uint8_t *bytes;
    size_t size;

    bytes = variable_list_bytes(&size);

    if (!bytes)
        return -1;

    if (!xapi_save_path)
        return -1;

    file = fopen(xapi_save_path, "w");

    if (!file)
        return -1;

    ret = fwrite(bytes, 1, size, file);

    if (ret != size)
        return -1;

    return 0;
}
