#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
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

#include "common.h"
#include "xapi.h"
#include "serializer.h"
#include "backends/backend.h"

#define XAPI_CODEC_DEBUG 1
#define XAPI_DEBUG 0

#define BIG_MESSAGE_SIZE (8 * PAGE_SIZE)

#define VM_UUID_MAX 36
char VM_UUID[VM_UUID_MAX];
bool xapi_uuid_initialized = false;

static char *UUID_ARG;

extern char root_path[PATH_MAX];
char socket_path[108];
bool socket_path_initialized = false;

/* The maximum number of digits in the Content-Length HTTP field */
#define MAX_CONTENT_LENGTH_DIGITS 16

#define HTTP_HEADER 							            \
    "POST / HTTP/1.1\r\n"                                                   \
    "Host: _var_lib_xcp_xapi\r\n"                                           \
    "Accept-Encoding: identity\r\n"                                         \
    "User-Agent: varstored/0.1\r\n"                                         \
    "Connection: close\r\n"                                                 \
    "Content-Type: text/xml\r\n"                                            \
    "Content-Length: %lu\r\n"                                               \
    "\r\n"

#define HTTP_BODY_SET_NVRAM_VARS                                                 \
	"<?xml version='1.0'?>"								                            \
	"<methodCall>"									                                \
	"<methodName>VM.set_NVRAM_EFI_variables</methodName>"				            \
		"<params>"								                                    \
			"<param><value><string>DUMMYSESSION</string></value></param>"	    \
			"<param><value><string>DUMMYVM</string></value></param>"	        \
			"<param><value><string>%s</string></value></param>"		                \
		"</params>"								                                    \
	"</methodCall>"

#define SOCKET_MAX 108
char socket_path[SOCKET_MAX];

int xapi_parse_arg(char *arg)
{
    char *p;

    if ( (p = strstr(optarg, "socket:")) != NULL )
    {
        p += 7;
        strncpy(socket_path, p, SOCKET_MAX);
        socket_path_initialized = true;
        return 0;
    }
    else if ( (p = strstr(optarg, "uuid:")) != NULL )
    {
        p += 5; 
        strncpy(VM_UUID, p, VM_UUID_MAX);
        xapi_uuid_initialized = true;
        return 0;
    }

    return 0;
}

int xapi_init(void)
{
    if ( !xapi_uuid_initialized )
    {
        ERROR("No uuid initialized passed as arg!\n");
        return -1;
    }

    return 0;
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

    if ( !response )
        return -1;

    p = strchr(response, ' ');

    if ( !p )
    {
        ERROR("Invalid HTTP in response\n");
        return -1;
    }

    status = strtol(p, NULL, 10);

    if ( status == LONG_MIN || status == LONG_MAX || status > INT_MAX )
    {
        ERROR("Bad http status: %lu\n", status);
        return -1;
    }

    return (int)status;
}

static char *response_body(char *response)
{
    char *body;

    if ( !response )
        return NULL;

    body = strstr(response, "\r\n\r\n");

    if ( !body )
        return NULL;
    
    return body + sizeof("\r\n\r\n") - 1;
}

int base64_to_blob(uint8_t *plaintext, size_t n, char *encoded, size_t encoded_size)
{

    size_t ret;

    if ( !plaintext || n == 0 || !encoded || encoded_size == 0 )
        return -1;

    DEBUG("n=%lu, encoded_size=%lu, encoded=%s\n", n, encoded_size, encoded);

    BIO *mem, *b64;

    b64 = BIO_new(BIO_f_base64());
    mem = BIO_new_mem_buf(encoded, encoded_size);

    mem = BIO_push(b64, mem);

    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(mem, BIO_CLOSE);

    ret = BIO_read(mem, plaintext, encoded_size);

    BIO_free_all(mem);

    if ( ret == 0 )
    {
        ERROR("No data decrypted!\n");
        return  -1;
    }

    return ret > INT_MAX ? -2 : (int) ret;
}

char *blob_to_base64(uint8_t *buffer, size_t length)
{
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *bufferPtr = NULL;
    char *b64text = NULL;

    if ( length <= 0 )
        goto cleanup;

    b64 = BIO_new(BIO_f_base64());
    if ( b64 == NULL )
        goto cleanup;

    bio = BIO_new(BIO_s_mem());
    if ( bio == NULL )
        goto cleanup;

    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(bio, BIO_CLOSE);

    if ( BIO_write(bio, (char*)buffer, (int)length) <= 0 )
        goto cleanup;

    if ( BIO_flush(bio) != 1 )
        goto cleanup;

    BIO_get_mem_ptr(bio, &bufferPtr);

    b64text = (char*) malloc((bufferPtr->length + 1) * sizeof(char));
    if ( b64text == NULL )
        goto cleanup;

    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';
    BIO_set_close(bio, BIO_NOCLOSE);

cleanup:
    BIO_free_all(bio);
    BUF_MEM_free(bufferPtr);

    return b64text;
}

size_t xapi_serialized_size(serializable_var_t *vars, size_t len)
{
    size_t size = 0;
    size_t i;
    
    for ( i=0; i<len; i++ )
        size += vars[i].variable_len + sizeof(vars[i].variable_len) +
                vars[i].data_len + sizeof(vars[i].data_len);

    return size;
}

int xapi_serialize(serializable_var_t *vars, size_t len, void *data, size_t size)
{
    serializable_var_t *var;
    size_t current_size = 0;
    size_t i;
    void *p;

    for ( i=0; i<len; i++ )
    {
        var = &vars[i];

        if ( current_size + var->data_len + var->variable_len + 
             sizeof(var->data_len) + sizeof(var->variable_len) > size )
             return -1;

        p = data + current_size;
        memcpy(p, &var->variable_len, sizeof(var->variable_len));
        current_size += sizeof(var->variable_len);

        p = data + current_size;
        memcpy(p, var->variable, var->variable_len);
        current_size += var->variable_len;

        p = data + current_size;
        memcpy(p, &var->data_len, sizeof(var->data_len));
        current_size += sizeof(var->data_len);

        p = data + current_size;
        memcpy(p, var->data, var->data_len);
        current_size += var->data_len;
    }

    return 0;
}

size_t blob_size(variable_t *variables, size_t n)
{
    size_t i, sz;
    variable_t *next;

    sz = 0;
    for ( i=0; i<n; i++ )
    {
        next = &variables[i];

        sz += next->namesz;
        sz += sizeof(next->namesz);
        sz += next->datasz;
        sz += sizeof(next->datasz);
    }

    return sz;
}

/**
 * Retrieves variables from db and stores in vars arg
 *
 * Returns the total bytes retrieved.
 */
static int retrieve_vars(variable_t *vars, size_t n)
{   
    int ret;
    size_t cnt = 0;
    variable_t *current, *next;

    memset(vars, 0, sizeof(*vars) * n);

    current = &vars[0];
    next = &vars[0];

    memset(current, 0, sizeof(*current));

    while ( cnt < n )
    {
        ret = backend_next(current, next);

        /* Error */
        if ( ret < 0 )
            return ret;

        /* Last variable */
        if ( ret == 0 )
            break;

        current = next;
        next++;
        cnt++;
    }

    /* Too many variables */
    if ( cnt > INT_MAX )
        return -1;

    DEBUG("%s: return cnt=%lu\n", __func__, cnt);
    return cnt;
}

static size_t sizeof_var(variable_t *var)
{
        return var->namesz + sizeof(var->namesz) + 
                var->datasz + sizeof(var->datasz);
}

int serialize_var(uint8_t **p, size_t n, variable_t *var)
{
    size_t used = 0;

    if ( sizeof(var->namesz) > n )
        return -1;

    memcpy(*p, &var->namesz, sizeof(var->namesz)); 
    *p += sizeof(var->namesz);
    used += sizeof(var->namesz);

    if ( var->namesz + used > n )
        return -1;

    memcpy(*p, var->name, var->namesz); 
    *p += var->namesz;
    used += var->namesz;

    if ( sizeof(var->datasz) + used > n )
        return -1;

    memcpy(*p, &var->datasz, sizeof(var->datasz)); 
    *p += sizeof(var->datasz);
    used += sizeof(var->datasz);

    if ( var->datasz + used > n )
        return -1;

    memcpy(*p, var->data, var->datasz); 
    *p += var->datasz;
    used += var->datasz;

    DEBUG("%s: used=%ld\n", __func__, used);

    return 0;
}

int from_vars_to_blob(uint8_t *buf, size_t bufsize, variable_t *vars, size_t vars_cnt)
{
    uint8_t *p;
    int i, ret;

    if ( !buf || bufsize <= 0 || !vars || vars_cnt == 0 )
        return -1;
    
    p = buf;

    for ( i=0; i<vars_cnt; i++ )
    {
        ret = serialize_var(&p, bufsize, &vars[i]);

        if ( ret < 0 )
        {
            ERROR("%s: buffer not big enough\n", __func__);
            return ret;
        }
    }
    
    return 0;
}

static inline void copy_field(void *dst, uint8_t **src, size_t n)
{
    memcpy(dst, *src, n);
    *src += n;
}

static inline int copy_name(variable_t *var, uint8_t **src)
{
    if ( var->namesz <= 0 || var->namesz >= MAX_VARNAME_SZ )
        return -1;

    copy_field(var->name, src, var->namesz);            
    var->name[var->namesz] = '\0';
    return 0;
}

static inline void copy_namesz(variable_t *var, uint8_t **src)
{
    var->namesz = unserialize_uintn(src);

    //copy_field(&var->namesz, src, sizeof(var->namesz));            
}

static inline int copy_data(variable_t *var, uint8_t **src)
{
    if ( var->datasz <= 0 || var->datasz >= MAX_VARDATA_SZ )
        return -1;

    copy_field(var->data, src, var->datasz);            
    var->data[var->datasz] = '\0';
    return 0;
}

static inline void copy_datasz(variable_t *var, uint8_t **src)
{
    copy_field(&var->datasz, src, sizeof(var->datasz));            
}

int unserialize_var(variable_t *var, uint8_t **src)
{
    int ret;

    var->namesz = unserialize_uintn(src);
    ret = copy_name(var, src);

    if ( ret < 0 )
        return ret;

    copy_datasz(var, src);

    ret = copy_data(var, src);
    if ( ret < 0 )
        return ret;

    return 0;
}

int from_blob_to_vars(variable_t *vars, size_t n, uint8_t *blob, size_t blob_sz)
{
    uint8_t *p;
    size_t cnt;
    const uint8_t *end = blob + blob_sz;
    variable_t *var;

    if ( !vars || !blob || n == 0 || blob_sz == 0 )
        return -1;

    cnt = 0;
    p = blob;
    var = vars;

    while ( p < end && cnt < n )
    {
        if ( p > end )
        {
            return -1;
        }

        unserialize_var(var, &p);

        cnt++;
        var++;
    }
    
    return cnt > INT_MAX ? -1 : (int)cnt;
}

static char *variables_base64(void)
{
    int rc;
    char *base64 = NULL;
    uint8_t *blob;
    size_t size;
    variable_t vars[MAX_VAR_COUNT];

    rc = retrieve_vars(vars, MAX_VAR_COUNT);
    if ( rc < 0 )
    {
        DEBUG("retrieve_vars err: %d\n", rc);
        return NULL;
    }

    if ( rc == 0 )
    {
        DEBUG("retrieve_vars no variables found: rc=%d\n", rc);
        return NULL;
    }

    size = blob_size(vars, rc);
    if ( size == 0 )
        return NULL;

    DEBUG("%s: size=%lu\n", __func__, size);

    blob = malloc(size);

    if ( !blob )
        return NULL;


    rc = from_vars_to_blob(blob, size, vars, (size_t)rc);
    if ( rc < 0 )
        return NULL;

#if XAPI_CODEC_DEBUG
    DPRINTF("0x");
    int i;
    for (i=0; i<16 * sizeof(unsigned long long); i += sizeof(unsigned long long))
    {
        unsigned long long val;
        memcpy(&val, blob + i, sizeof(unsigned long long));

        DPRINTF("%llx", val);
    }
    DPRINTF("\n");
#endif

    if ( rc < 0 )
        goto end;

    base64 = blob_to_base64(blob, size);

end:
    free(blob);
    return base64;
}

static int create_header(size_t body_len, char *message, size_t message_size)
{
    int ret;

    ret = snprintf(message, message_size, HTTP_HEADER, body_len);

    if ( ret < 0 )
    {
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

    base64 = variables_base64();
    if ( !base64 )
        return -1;

    base64_size = strlen(base64);
    body_len = sizeof(HTTP_BODY_SET_NVRAM_VARS) + base64_size - 1;
    DEBUG("sizeof(HTTP)=%lu, base64_size=%lu\n", sizeof(HTTP_BODY_SET_NVRAM_VARS), base64_size);
    DEBUG("body_len=%lu\n", body_len);

    body = malloc(body_len);

    if ( !body )
    {
        free(base64);
        return -1;
    }

    ret = snprintf(body, body_len, HTTP_BODY_SET_NVRAM_VARS, base64);

    if ( ret < 0 )
    {
        ret = -1;
        goto end;
    }


    DEBUG("body: %s\n", body);

    body_len = strlen(body);

    hdr_len = create_header(body_len, buffer, n);
    if ( hdr_len < 0 )
    {
        ret = -1;
        goto end;
    }

    DEBUG("%s: size=%lu\n", __func__, hdr_len + body_len);

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
    
    if ( fd < 0 )
    {
        ERROR("socket() failed: %d\n", fd);
        return fd;
    }

    ret = connect(fd, (struct sockaddr*)&saddr, sizeof(saddr));

    if ( ret < 0 )
    {
        close(fd);
        ERROR("connect() failed: %d\n", ret);
        return ret;
    }

    ret = write(fd, message, strlen(message));

    if ( ret < 0 )
    {
        close(fd);
        ERROR("write() failed: %d\n", ret);
        return ret;
    }

    ret = read(fd, buf, bufsz);

    if ( ret < 0 )
    {
        close(fd);
        ERROR("read() failed: %d\n", ret);
        return ret;
    }

    
    close(fd);
    buf[ret] = '\0';
    return http_status(buf);
}

int xapi_set_efi_vars(void)
{
    char buffer[BIG_MESSAGE_SIZE];
    int ret;


    ret = build_set_efi_vars_message(buffer, BIG_MESSAGE_SIZE);
    if ( ret < 0 )
        return ret;

    
    DEBUG("%s: request:\n%s\n", __func__, buffer);
    ret = send_request(buffer, buffer, BIG_MESSAGE_SIZE);
    DEBUG("%s: response:\n%s\n", __func__, buffer);

    return ret == 200 ? 0 : -1;
}

#define HTTP_LOGIN                                                              \
    "POST / HTTP/1.1\r\n"                                                       \
    "Host: _var_lib_xcp_xapi\r\n"                                               \
    "Accept-Encoding: identity\r\n"                                             \
    "User-Agent: varstored/0.1\r\n"                                             \
    "Connection: close\r\n"                                                     \
    "Content-Type: text/xml\r\n"                                                \
    "Content-Length: 307\r\n"                                                   \
    "\r\n"                                                                      \
    "<?xml version='1.0'?>"                                                     \
    "<methodCall>"                                                              \
        "<methodName>session.login_with_password</methodName>"                  \
        "<params>"                                                              \
            "<param><value><string>root</string></value></param>"               \
            "<param><value><string></string></value></param>"                   \
            "<param><value><string></string></value></param>"                   \
            "<param><value><string></string></value></param>"                   \
        "</params>"                                                             \
    "</methodCall>"

int xapi_connect(void)
{
    char response[4096];
    int ret;

    ret = send_request(HTTP_LOGIN, response, 4096);
    if ( ret < 0 )
        return ret;

    return ret;
}

void save_time(void)
{
#if 0
    time_t ret;

    /* Time since last saved */
    ret = time((time_t *)0x0);
    DAT_0060d7c0 = DAT_0060d7c0 + ((int)ret - (int)_DAT_0060d8a0) * 2;
    _DAT_0060d8a0 = ret;
    if (DAT_0060d7c0 < 0x65)
    {
        if (DAT_0060d7c0 == 0)
        {
            response = (void *)0x0;
            nanosleep((timespec *)&response,(timespec *)0x0);
            _DAT_0060d8a0 = time((time_t *)0x0);
        }
        else
        {
            DAT_0060d7c0 = DAT_0060d7c0 - 1;
        }
    }
    else
    {
        DAT_0060d7c0 = 99;
    }
#endif
}

int xapi_request(char *response, size_t response_sz, const char *format, ...)
{
    va_list ap;
    char message[BIG_MESSAGE_SIZE];
    char body[3*1024];
    int hdr_len;
    size_t body_len;
    int ret;

    va_start(ap, format);
    ret = vsnprintf(body, 3*1024, format, ap);
    va_end(ap);

    if ( ret < 0 )
        return ret;

    body_len = ret;

    hdr_len = create_header(body_len, message, BIG_MESSAGE_SIZE);

    if ( hdr_len < 0 )
    {
        return -1;
    }

    strncat(message, body, BIG_MESSAGE_SIZE);

    if ( strlen(message) ==  (BIG_MESSAGE_SIZE-1) )
    {
        WARNING("message length is exactly, equal to buffer length.  May have lost bytes!\n");
    }

    DEBUG("%s: request, ret=%d\n%s\n", __func__, ret, message);
    ret = send_request(message, response, response_sz);
    DEBUG("%s: response, ret=%d\n%s\n", __func__, ret, response);

    return ret;
}

static bool success(char *body)
{
    size_t len;
    int ret;

    xmlDoc *doc;
    xmlXPathObject *obj;
    xmlXPathContext *context;
    xmlChar *string;


    if ( !body )
        return false;

    len = strlen(body);

    doc = xmlReadMemory(body, len, "dummy.xml", 0, 0);

    if ( !doc )
    {
        ERROR("xmlReadMemory() error\n");
        return false;
    }

    context = xmlXPathNewContext(doc);
    if ( !context )
    {
        ERROR("xmlXPathNewContext() error\n");
        return false;
    }

    obj = xmlXPathEvalExpression((xmlChar*)
        "/methodResponse/params/param/value/struct/member[1]/value", context);

    if ( !obj )
    {
        ERROR("xmlXPathEvalExpression() error\n");
        xmlXPathFreeContext(context);
        return false;
    }

    string = xmlNodeGetContent(obj->nodesetval->nodeTab[0]->xmlChildrenNode);

    if ( !string )
    {
        ERROR("xmlNodeGetContent() error\n");
        xmlXPathFreeContext(context);
        xmlXPathFreeObject(obj);
        return false;
    }

    DEBUG("%s: string=%s\n", __func__, (char*)string);
    ret = memcmp(string, "Success", 8);
    DEBUG("%s: ret=%d\n", __func__, ret);

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

    if ( !body || !dest )
    {
        DEBUG("%s: null ptr args\n", __func__);
        return -1;
    }


    doc = xmlReadMemory(body, strlen(body), "dummy.xml", 0, 0);

    if ( !doc )
    {
        DEBUG("%s: xmlReadMemory() error\n", __func__);
        return -1;
    }

    context = xmlXPathNewContext(doc);

    if ( !context )
    {
        DEBUG("%s: xmlXPathNewContext() error\n", __func__);
        xmlFree(doc);
        return -1;
    }

    obj = xmlXPathEvalExpression((xmlChar*)"/methodResponse/params/param/value/struct/member[2]/value", context);

    if ( !obj )
    {
        DEBUG("%s: xmlXPathEvalExpression() error\n", __func__);
        xmlXPathFreeContext(context);
        xmlFreeDoc(doc);
        return -1;
    }


    string = xmlNodeGetContent((xmlNodePtr)obj->nodesetval->nodeTab[0]);
    strncpy(dest, (char*)string, n);

    xmlFree(string);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(context);
    xmlFreeDoc(doc);

    return 0;
}


int get_response_content(char *response, char *outstr, size_t n)

{
    char *body;

    if ( !response )
    {
        DEBUG("%s, response=(null)\n", response);
        return -1;
    }

    body = response_body(response);

    if ( !success(body) )
    {
        DEBUG("Response from XAPI is not Success\n");
        return -2;
    }

    if ( outstr && n > 0 )
        return get_value(body, outstr, n);

    return 0;
}

                                                                          

int set_efi_vars(char *session_id, char *b64)
{
    int ret;
    char response[1024] = {0};
    int status;

    ret = xapi_vm_get_by_uuid(session_id);

    if ( ret < 0 )
        return ret;

    status = xapi_request(response, 1024,
        "<?xmlversion=\'1.0\'?>"
        "<methodCall>"
        "<methodName>VM.set_NVRAM_EFI_variables</methodName>"
            "<params>"
                "<param><value><string>%s</string></value></param>"
                "<param><value><string>%s</string></value></param>"
                "<param><value><string>%s</string></value></param>"
            "</params>"
        "</methodCall>",
        session_id, VM_UUID, b64);

    if ( status != 200 )
    {
        ERROR("Failed to set NVRAM EFI vars\n");
        return -1;
    }

    return success(response_body(response)) ? 0 : -1;
}

int xapi_vm_get_by_uuid(char *session_id)
{
    int status, ret;
    char response[1024] = {0};

    status = xapi_request(response, 1024,
        "<?xmlversion=\'1.0\'?>"
        "<methodCall>"
            "<methodName>VM.get_by_uuid</methodName>"
            "<params>"
                "<param><value><string>%s</string></value></param>"
                "<param><value><string>%s</string></value></param>"
            "</params>"
        "</methodCall>",
        session_id, VM_UUID);

    if ( status != 200 )
    {
        ERROR("Failed to communicate with XAPI\n");
        return -1;
    }

    ret = get_response_content(response, NULL, 0);
    if ( ret < 0 )
    {
        ERROR("failed to lookup VM\n");
        return ret;
    }

    return ret;
}

int session_login(char *session_id, size_t n)
{
    int status, ret;
    char response[1024] = {0};

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
            "</methodCall>"
    );

    if ( status != 200 )
    {
        ERROR("failed to login to xapi, status=%d\n", status);
        return -1;
    }

    ret = get_response_content(response, session_id, n);
    
    if ( ret < 0 )
    {
        ERROR("failed to login to xapi, ret=%d\n", ret);
        return ret;
    }

    return 0;
}

int session_logout(char *session_id)
{
    int status;
    char response[1024] = {0};

    status = xapi_request(
        response, 1024,
        "<?xmlversion=\'1.0\'?>"
        "<methodCall>"
            "<methodName>session.logout</methodName>"
            "<params>"
                "<param><value><string>%s</string></value></param>"
            "</params>"
        "</methodCall>",
        session_id);

    if ( status != 200 )
    {
        ERROR("failed to logout of xapi session\n");
        return -1;
    }

    if ( !success(response_body(response)) )
    {
        ERROR("failed to logout of xapi session\n");
        return -1;
    }

    return 0;
}

/**
 * Return the EFI vars string from the XML response for VM.get_NVRAM XAPI
 * request.
 *
 * buffer: the destination buffer
 * n: the size of buffer
 * body: the null-terminated XML body
 */
int base64_from_response_body(char *buffer, size_t n, char *body)
{
    size_t len;
    xmlXPathObject *obj;
    xmlDoc *doc;
    xmlXPathContext *context;
    xmlChar *string;

    len = strlen(body);

    DEBUG("%s: len=%lu\n", __func__, len);

    doc = xmlReadMemory(body, len-1, "dummy.xml", NULL, 0);

    if ( !doc )
    {
        ERROR("null doc! err=%d, errstring=%s\n", errno, strerror(errno));
        return -1;
    }

    if ( errno != 0 )
        return errno;

    context = xmlXPathNewContext(doc);

    if ( !context )
    {
        free(doc);

        DEBUG("xmlXPathNewContext() failed!\n");
        return -1;
    }

    obj = xmlXPathEvalExpression((xmlChar*)
        "/methodResponse/params/param/value/struct/member[1]/value", context);

    if ( !obj )
    {
        DEBUG("xmlXPathEvalExpression() failed!\n");
        free(doc);
        xmlXPathFreeContext(context);

        return -1;
    }

    string = xmlNodeGetContent((xmlNodePtr)obj->nodesetval->nodeTab[0]);
    if ( memcmp(string, "Success", 8) != 0 )
    {
        INFO("xapi response, no success!\n");
        free(doc);
        xmlXPathFreeContext(context);
        xmlXPathFreeObject(obj);

        return -1;
    }

    xmlFree(string);
    xmlXPathFreeObject(obj);

    obj = xmlXPathEvalExpression((xmlChar *)
        "/methodResponse/params/param/value/struct/member/value/struct/member[name=\"EFI-variables\"]/value",
        context);

    if ( !obj || !obj->nodesetval )
    {
        free(doc);
        free(context);

        DEBUG("EFI-vars not found in response\n");

        return -1;
    }

    string = xmlNodeGetContent(obj->nodesetval->nodeTab[0]);

    strncpy(buffer, (char*)string, n);

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

    return base64_from_response_body(buffer, n, body);
}

static int get_nvram(char *session_id, char *buffer, size_t n)
{
    int status;
    char response[BIG_MESSAGE_SIZE] = {0};

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

    if ( status != 200 )
        return -1;

    return base64_from_response(buffer, n, response);
}

/**
 * Returns 0 if successfully retrieved variables.
 *
 * Returns negative errno for errors.
 */
int xapi_get_efi_vars(variable_t *vars, size_t n)

{
    int retries = 5;
    int ret;
    char session_id[512];
    uint8_t plaintext[BIG_MESSAGE_SIZE];
    char b64[BIG_MESSAGE_SIZE];

    ret = session_login(session_id, 512);

    while ( ret < 0 && retries > 0 )
    {
        usleep(100000);
        ret = session_login(session_id, 512);
        retries--;
    }

    if ( ret < 0 )
        return ret;

    ret = xapi_vm_get_by_uuid(session_id);

    if ( ret < 0 )
        return ret;

    ret = get_nvram(session_id, b64, BIG_MESSAGE_SIZE);

    if ( ret < 0 )
    {
        ERROR("failed to get NVRAM from xapi, ret=%d\n", ret);
        return ret;
    }

    ret = base64_to_blob(plaintext, BIG_MESSAGE_SIZE, b64, strlen(b64)); 
    
    if ( ret < 0 )
        return ret;

#if XAPI_CODEC_DEBUG
    int i;

    DPRINTF("0x");
    for (i=0; i<16 * sizeof(unsigned long long); i += sizeof(unsigned long long))
    {
        unsigned long long val;
        memcpy(&val, plaintext + i, sizeof(unsigned long long));

        DPRINTF("%llx", val);
    }
    DPRINTF("\n");
#endif

    ret = from_blob_to_vars(vars, n, plaintext, (size_t)ret);

    if ( ret < 0 )
        return ret;

    return ret;
}

int xapi_set_variables(void)
{
    char *b64;
    int ret;
    char session_id[512];

    if ( UUID_ARG == 0 )
        return 1;

    save_time();

    ret = session_login(session_id, 512);

    if ( ret < 0 )
    {
        usleep(100000);
        ret = session_login(session_id, 512);
        if ( ret < 0 )
            return ret;
    }

    ret = xapi_vm_get_by_uuid(session_id);

    if ( ret < 0 )
        return ret;

    b64 = variables_base64();

    ret = set_efi_vars(session_id, b64);

    if ( ret < 0 )
        goto free_b64;

    ret = session_logout(session_id);

    if ( ret < 0 )
        goto free_b64;

free_b64:
    free(b64);

    return ret;
}

int xapi_efi_vars(variable_t *variables, size_t sz)
{
    (void)variables;
    (void)sz;

    return 0;
}
