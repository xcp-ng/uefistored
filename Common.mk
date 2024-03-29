PKGS := glib-2.0    \
        libxml-2.0  \
        libssl      \
        libcrypto   \
        libseccomp

SRCS :=                                                         \
        src/common.c                                            \
        src/depriv.c                                            \
        src/log.c                                               \
        src/serializer.c                                        \
        src/storage.c                                           \
        src/uefi/auth.c                                         \
        src/uefi/authlib.c                                      \
        src/uefi/types.c                                        \
        src/uefi/utils.c                                        \
        src/uefi/guids.c                                        \
        src/uefi/pkcs7_verify.c                                 \
        src/varnames.c                                          \
        src/variable.c                                          \
        src/xapi.c                                              \
        src/xen_variable_server.c
