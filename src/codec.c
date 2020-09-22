
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
