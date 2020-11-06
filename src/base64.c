#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "base64.h"
#include "log.h"

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
    BUF_MEM *buffer_ptr = NULL;
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

    BIO_get_mem_ptr(bio, &buffer_ptr);

    b64text = (char *)malloc((buffer_ptr->length + 1) * sizeof(char));
    if (b64text == NULL)
        goto cleanup;

    memcpy(b64text, buffer_ptr->data, buffer_ptr->length);
    b64text[buffer_ptr->length] = '\0';
    BIO_set_close(bio, BIO_NOCLOSE);

cleanup:
    BIO_free_all(bio);
    BUF_MEM_free(buffer_ptr);

    return b64text;
}
