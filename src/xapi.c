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
#include "backends/filedb.h"

static char *VM_UUID;
static char *UUID_ARG;

extern char root_path[PATH_MAX];
extern char socket_path[108];

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
			"<param><value><string>VARSTOREDSESSION</string></value></param>"	    \
			"<param><value><string>VARSTOREDVM</string></value></param>"	        \
			"<param><value><string>%s</string></value></param>"		                \
		"</params>"								                                    \
	"</methodCall>"


char *blob_to_base64(char *buffer, size_t length)
{
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *bufferPtr = NULL;
    char *b64text = NULL;

    if(length <= 0)
        goto cleanup;

    b64 = BIO_new(BIO_f_base64());
    if(b64 == NULL)
        goto cleanup;

    bio = BIO_new(BIO_s_mem());
    if(bio == NULL)
        goto cleanup;

    bio = BIO_push(b64, bio);

    if(BIO_write(bio, buffer, (int)length) <= 0)
        goto cleanup;

    if(BIO_flush(bio) != 1)
        goto cleanup;

    BIO_get_mem_ptr(bio, &bufferPtr);

    b64text = (char*) malloc((bufferPtr->length + 1) * sizeof(char));
    if(b64text == NULL)
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

static size_t blob_size(size_t *outsize)
{
    int ret;
    size_t cnt = 0;
    size_t len = 0;
    variable_t variables[MAX_VAR_COUNT];
    variable_t *current, *next;

    memset(variables, 0, sizeof(variables));

    /* Retrieve DB contents */
    current = &variables[0];
    next = &variables[0];
    
    do {
        ret = filedb_variable_next(current, next);
        
        if ( ret > 0 )
        {
            len += next->namesz;
            len += sizeof(next->namesz);
            len += next->datasz;
            len += sizeof(next->datasz);
            cnt += 1;
        }

        current = next;
        next++;
    } while ( ret > 0 && next != &variables[MAX_VAR_COUNT - 1] );

    if ( ret < 0 )
        return -1;

    if ( len == 0 )
        return -1;

    *outsize = len;

    return 0;
}

static int convert_to_blob(uint8_t *buf, size_t bufsize)
{
    int ret;
    uint8_t *p;
    size_t cnt = 0;
    size_t len = 0;
    variable_t variables[MAX_VAR_COUNT];
    variable_t *current, *next;

    memset(variables, 0, sizeof(variables));

    /* Retrieve DB contents */
    current = &variables[0];
    next = &variables[0];
    
    do {
        ret = filedb_variable_next(current, next);
        
        if ( ret > 0 )
        {
            len += next->namesz;
            len += sizeof(next->namesz);
            len += next->datasz;
            len += sizeof(next->datasz);
            cnt += 1;
        }

        current = next;
        next++;
    } while ( ret > 0 && next != &variables[MAX_VAR_COUNT - 1] );

    if ( ret < 0 )
        return -1;

    if ( len == 0 || len > bufsize )
        return -1;

    /* Serialize DB contents */
    p = buf;

    int i;
    for ( i=0; i<cnt; i++ )
    {
        memcpy(p, &variables[i].namesz, sizeof(variables[i].namesz)); 
        p += sizeof(variables[i].namesz);

        memcpy(p, variables[i].name, variables[i].namesz); 
        p += variables[i].namesz;

        memcpy(p, &variables[i].datasz, sizeof(variables[i].datasz)); 
        p += sizeof(variables[i].datasz);

        memcpy(p, variables[i].data, variables[i].datasz); 
        p += variables[i].datasz;
    }
    
    return 0;
}

static char *variables_base64(void)
{
    int rc;
    char *base64 = NULL;
    uint8_t *blob;
    size_t size;


    rc = blob_size(&size);
    if ( rc < 0 )
        return NULL;

    blob = malloc(size);

    if ( !blob )
        return NULL;

    rc = convert_to_blob(blob, size);

    if ( rc < 0 )
        goto end;

    base64 = blob_to_base64((char *)blob, size);

end:
    free(blob);
    return base64;
}

static char *build_header(size_t body_len, size_t *hdr_len)
{
    int ret;
    size_t maxlen = sizeof(HTTP_HEADER) + MAX_CONTENT_LENGTH_DIGITS;
    char *hdr;

    hdr = malloc(maxlen);

    if ( !hdr )
    {
        return NULL;
    }

    ret = snprintf(hdr, maxlen, HTTP_HEADER, body_len);

    if ( ret < 0 )
    {
        free(hdr);
        *hdr_len = 0;
        return NULL;
    }

    *hdr_len = ret;

    return hdr;
}

static char *build_set_efi_vars_message(void)
{
    int ret;
    char *message = NULL;
    char *base64;
    char *body;
    //char hdr[sizeof(HTTP_HEADER) + MAX_CONTENT_LENGTH_DIGITS];
    size_t base64_size, body_len, hdr_len;
    char *hdr;

    base64 = variables_base64();
    if ( !base64 )
        return NULL;

    base64_size = strlen(base64);
    body_len = sizeof(HTTP_BODY_SET_NVRAM_VARS) + base64_size - 1;

    body = malloc(body_len);

    if ( !body )
    {
        free(base64);
        return NULL;
    }

    ret = snprintf(body, body_len, HTTP_BODY_SET_NVRAM_VARS, base64);

    if ( ret < 0 )
        goto end;

    body_len = ret;

    hdr = build_header(body_len, &hdr_len);
    if ( !hdr )
        goto end;
    
    message = malloc(body_len + hdr_len + 1); 
    if ( !message )
        goto end;

    strncpy(message, hdr, hdr_len);
    strncpy(message + hdr_len, body, body_len);
    message[body_len + hdr_len] = '\0';

end:
    free(body);
    free(hdr);
    free(base64);

    return message;
}

static int send_request(char *message, char *buf, size_t bufsz)
{
    int ret, fd;
    struct sockaddr_un saddr;

    TRACE();
    saddr.sun_family = AF_UNIX;
    strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path));

    TRACE();
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    
    if ( fd < 0 )
        return fd;
    TRACE();

    ret = connect(fd, (struct sockaddr*)&saddr, sizeof(saddr));
    if ( ret < 0 )
        return ret;

    TRACE();
    ret = write(fd, message, strlen(message));

    if ( ret < 0 )
        return ret;

    TRACE();
    ret = read(fd, buf, bufsz);
    if ( ret < 0 )
        return ret;

    /* TODO: process the HTTP status code */

    TRACE();
    DEBUG("RESPONSE:\n%s\n", buf);

    return ret;
}

int xapi_set_efi_vars(void)
{
    char response[4096];
    int ret;
    char *message;

    message = build_set_efi_vars_message();

    if ( !message )
        return -1;

    ret = send_request(message, response, 4096);

    free(message);

    return ret;
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


int xapi_request(char **response, const char *format, ...)
{
    va_list ap;
    char body[4096] = {0};
    char *hdr, *message;
    size_t hdr_len, body_len;
    int ret;

    va_start(ap, format);
    ret = vsnprintf(body, 4096, format, ap);
    va_end(ap);

    TRACE();
    if ( ret < 0 )
        return ret;

    TRACE();
    body_len = ret;

    hdr = build_header(body_len, &hdr_len);

    if ( !hdr )
    {
        return -1;
    }
    TRACE();

    message = strncat(hdr, body, hdr_len + body_len + 1);
    message[hdr_len + body_len + 1] = '\0';

    DEBUG("%s: request\n%s\n", __func__, message);

    *response = malloc(4096);

    TRACE();
    ret = send_request(message, *response, 4096);
    DEBUG("%s: response\n%s\n", __func__, *response);

    free(message);
    free(hdr);
    free(body);

    return ret;
}

int get_response_content(char* response, void *content)
{
    (void)response;
    (void)content;

    return 0;
}

int set_efi_vars(char *session_id, char *b64)
{
    char *response = NULL;
    int status, ret;

    if ( !VM_UUID )
    {
        ERROR("no VM_UUID set!\n");
        return -1;
    }

    status = xapi_request(&response,
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

    ret = get_response_content(response, NULL);

    if ( ret < 0 )
    {
        free(response);
        ERROR("Failed to set NVRAM EFI vars\n");
        return ret;
    }

    return 0;
}

int global_set_vm_uuid(char *session_id)
{
    int status, ret;
    char *response = NULL;

    if ( VM_UUID )
        return 0;

    status = xapi_request(&response,
        "<?xmlversion=\'1.0\'?>"
        "<methodCall>"
            "<methodName>VM.get_by_uuid</methodName>"
            "<params>"
                "<param><value><string>%s</string></value></param>"
                "<param><value><string>%s</string></value></param>"
            "</params>"
        "</methodCall>",
        session_id, &VM_UUID);

    if ( status != 200 )
    {
        ERROR("Failed to communicate with XAPI\n");
        return -1;
    }

    ret = get_response_content(response, &VM_UUID);
    if ( ret < 0 )
    {
        ERROR("failed to lookup VM\n");
    }

    free(response);
    return ret;
}

int session_login(char **session_id)
{
    int status, ret;
    char *response = NULL;

    status = xapi_request(&response,
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
        ERROR("failed to login to xapi\n");
        return -1;
    }

    ret = get_response_content(response, &session_id);
    
    if ( ret < 0 )
    {
        ERROR("failed to login to xapi\n");
    }

    free(response);
    return 0;
}

int session_logout(char *session_id)
{
    int status, ret;
    char *response = NULL;

    status = xapi_request(
        &response,
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

    ret = get_response_content(response, NULL);

    if ( ret < 0 )
    {
        ERROR("failed to logout of xapi session\n");
    }

    free(response);
    return ret;
}

static int get_nvram(char *session_id)
{
    int status;
    size_t len;
    xmlXPathObject *obj;
    xmlDoc *doc;
    xmlXPathContext *context;
    xmlChar *string;
    char *response;

    status = xapi_request(&response,
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

    len = strlen(response);

    doc = xmlReadMemory(response, len, "dummy.xml", 0, 0);
    if ( !doc )
    {
        free(response);
        return -1;
    }

    context = xmlXPathNewContext(doc);
    if ( !context )
    {
        free(response);
        free(doc);

        return -1;
    }

    obj = xmlXPathEvalExpression((xmlChar*)
        "/methodResponse/params/param/value/struct/member[1]/value", context);

    if ( !obj )
    {
        free(response);
        free(doc);
        free(context);

        return -1;
    }

    string = xmlNodeGetContent((xmlNodePtr)obj->nodesetval->nodeTab[0]);
    if ( memcmp(string, "Success", 8) != 0 )
    {
        free(response);
        free(doc);
        free(context);
        xmlXPathFreeObject(obj);

        return -1;
    }

    xmlFree(string);
    xmlXPathFreeObject(obj);

    obj = xmlXPathEvalExpression((xmlChar *)
        "/methodResponse/params/param/value/struct/member/value/struct/member[name=\"EFI-variables\"]/value"
        , context);

    if ( !obj )
    {
        free(response);
        free(doc);
        free(context);

        return -1;
    }

    string = xmlNodeGetContent((xmlNodePtr)obj->nodesetval->nodeTab[0]);

    DEBUG("string: %s\n", string);

    xmlFree(string);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(context);
    xmlFreeDoc(doc);
    free(response);

    return 0;
}


int xapi_get_efi_vars(void)

{
    int ret;
    char *session_id;

    TRACE();

    ret = session_login(&session_id);

    if ( ret < 0 )
        return ret;
    TRACE();

    if ( !VM_UUID )
    {
    TRACE();
        ret = global_set_vm_uuid(session_id);

        if ( ret < 0 )
            goto free_session_id;
    }

    TRACE();
    ret = get_nvram(session_id);
    if ( ret < 0 )
    {
        ERROR("failed to get NVRAM from xapi\n");
    }

    TRACE();
free_session_id:
    free(session_id);

    TRACE();
    return 0;
}

int xapi_set_variables(void)
{
    char *b64;
    int ret;
    char *session_id;

    if ( UUID_ARG == 0 )
        return 1;

    save_time();

    ret = session_login(&session_id);

    if ( ret < 0 )
        return ret;

    if ( !VM_UUID )
    {
        ret = global_set_vm_uuid(session_id);

        if ( ret < 0 )
            goto free_session_id;
    }

    b64 = variables_base64();

    ret = set_efi_vars(session_id, b64);

    if ( ret < 0 )
        goto free_b64;

    ret = session_logout(session_id);

    if ( ret < 0 )
        goto free_b64;

free_b64:
    free(b64);

free_session_id:
    free(session_id);

    return ret;
}

int xapi_efi_vars(variable_t *variables, size_t sz)
{
    (void)variables;
    (void)sz;

    return 0;
}
