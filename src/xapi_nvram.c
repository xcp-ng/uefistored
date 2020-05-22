#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "xapi_nvram.h"

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
    uint8_t *buf, *p;
    size_t cnt = 0;
    size_t len = 0;
    variable_t variables[MAX_VAR_COUNT] = {0};
    variable_t *current, *next;

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
    variable_t variables[MAX_VAR_COUNT] = {0};
    variable_t *current, *next;

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
    char *blob;
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

int xapi_nvram_set_efi_vars(void)
{
    int ret;
    char *base64;
    char body[4096] = { 0 };
    size_t base64_size, body_len;

    base64 = variables_base64();
    if ( !base64 )
        return -1;

    base64_size = strlen(base64);

    printf("base64_size=%lu\n", base64_size);
    printf("sz1=%lu\n", sizeof(HTTP_BODY_SET_NVRAM_VARS));

    body_len = sizeof(HTTP_BODY_SET_NVRAM_VARS) - 1;
/*
    body = malloc(body_len + 1);
    if ( !body )
    {
        free(base64);
        return ret;
    }
*/

    ret = snprintf(body, 4096, HTTP_BODY_SET_NVRAM_VARS, base64);

    if ( ret < 0 )
        goto end;

    if ( ret !=  body_len)
    {
        ret = -1;
        goto end;
    }

end:
//    free(body);
    free(base64);

    return ret;
}
