#include <openssl/bio.h>
#include <openssl/evp.h>

#include "xapi_nvram.h"

#define SET_NVRAM_EFI_VARS_TEMPLATE 							            \
    "POST / HTTP/1.1\r\n"                                                   \
    "Host: _var_lib_xcp_xapi\r\n"                                           \
    "Accept-Encoding: identity\r\n"                                         \
    "User-Agent: varstored/0.1\r\n"                                         \
    "Connection: close\r\n"                                                 \
    "Content-Type: text/xml\r\n"                                            \
    "Content-Length: %lu\r\n"                                               \
    "\r\n"                                                                  \
	"<?xml version='1.0'?>"								                    \
	"<methodCall>"									                        \
	"<methodName>VM.set_NVRAM_EFI_variables</methodName>"				    \
		"<params>"								                            \
			"<param><value><string>VARSTOREDSESSION</string></value></param>"	\
			"<param><value><string>VARSTOREDVM</string></value></param>"	    \
			"<param><value><string>%s</string></value></param>"		        \
		"</params>"								                            \
	"</methodCall>"

uint8_t *encode_base64(unsigned char *data, int len, int *lenoutput)
{
    BIO *buf, *mem;
    uint8_t* output;
    int res = 0;

    buf = BIO_new(BIO_f_base64());
    BIO_set_flags(buf, BIO_FLAGS_BASE64_NO_NL);

    mem = BIO_new(BIO_s_mem());

    BIO_push(buf, mem);

    while( true )
    {
        res = BIO_write(buf, data, len);
        if ( res > 0 )
            break;

        if( !BIO_should_retry(buf) )
            return NULL;
    }

    BIO_flush(buf);

    // get a pointer to mem's data
    *lenoutput = BIO_get_mem_data(mem, (unsigned char*)&output);

    return output;
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
    variable_t variables[MAX_VAR_COUNT];
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
    variable_t variables[MAX_VAR_COUNT];
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

int xapi_nvram_set_efi_vars(void)
{
    int ret;
    uint8_t *buf;
    char *b64;
    int len;
    size_t size;


    ret = blob_size(&size);
    if ( ret < 0 )
        return ret;

    buf = malloc(size);

    ret = convert_to_blob(buf, size);
    if ( ret < 0 )
        return ret;

    b64 = encode_base64((char *)buf, size, &len);
    printf("%s\n", b64);

    free(buf);
    free(b64);
}
