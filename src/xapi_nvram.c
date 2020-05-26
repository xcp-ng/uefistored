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

#include "xapi_nvram.h"
#include "backends/filedb.h"

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

size_t xapi_nvram_serialized_size(serializable_var_t *vars, size_t len)
{
    size_t size = 0;
    size_t i;
    
    for ( i=0; i<len; i++ )
        size += vars[i].variable_len + sizeof(vars[i].variable_len) +
                vars[i].data_len + sizeof(vars[i].data_len);

    return size;
}

int xapi_nvram_serialize(serializable_var_t *vars, size_t len, void *data, size_t size)
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

static char *build_set_efi_vars_message(void)
{
    int ret;
    char *message = NULL;
    char *base64;
    char *body;
    char hdr[sizeof(HTTP_HEADER) + MAX_CONTENT_LENGTH_DIGITS];
    size_t base64_size, body_len, hdr_len;

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

    ret = snprintf(hdr, sizeof(hdr), HTTP_HEADER, body_len);

    if ( ret < 0 )
        goto end;

    hdr_len = ret;

    message = malloc(body_len + hdr_len + 1); 
    if ( !message )
        goto end;

    strncpy(message, hdr, hdr_len);
    strncpy(message + hdr_len, body, body_len);
    message[body_len + hdr_len] = '\0';

end:
    free(body);
    free(base64);

    return message;
}

static int send_set_efi_vars_message(char *message)
{
    char buf[4096];
    int ret, fd;
    struct sockaddr_un saddr;

    saddr.sun_family = AF_UNIX;
    strncpy(saddr.sun_path, socket_path, sizeof(saddr.sun_path));

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    
    if ( fd < 0 )
        return fd;

    ret = connect(fd, (struct sockaddr*)&saddr, sizeof(saddr));
    if ( ret < 0 )
        return ret;

    ret = write(fd, message, strlen(message));

    if ( ret < 0 )
        return ret;

    ret = read(fd, buf, sizeof(buf));
    if ( ret < 0 )
        return ret;

    DEBUG("RESPONSE:\n%s\n", buf);

    return ret;
}

int xapi_nvram_set_efi_vars(void)
{
    int ret;
    char *message;

    message = build_set_efi_vars_message();

    if ( !message )
        return -1;

    ret = send_set_efi_vars_message(message);

    free(message);

    return ret;
}
