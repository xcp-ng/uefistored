#ifndef __H_BASE64_
#define __H_BASE64_

#include <stdint.h>
#include <stddef.h>

char *bytes_to_base64(uint8_t *buffer, size_t length);
int base64_to_bytes(uint8_t *plaintext, size_t n, char *encoded,
                    size_t encoded_size);

#endif // __H_BASE64_
