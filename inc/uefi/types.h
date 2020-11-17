#ifndef __H_UEFITYPES_
#define __H_UEFITYPES_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef char CHAR8;
typedef uint16_t CHAR16;

typedef uint8_t UTF8;
typedef uint16_t UTF16;

typedef uint16_t UINT16;
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef int32_t INT32;
typedef uint64_t UINTN;
typedef int64_t INTN;

typedef bool BOOLEAN;
typedef void VOID;

#define OFFSET_OF(TYPE, Field) ((uint64_t) & (((TYPE *)0)->Field))

//
// Processor specific defines
//
#define MAX_BIT 0x8000000000000000ULL
#define MAX_2_BITS 0xC000000000000000ULL

//
// Maximum legal Itanium-based address
//
#define MAX_ADDRESS 0xFFFFFFFFFFFFFFFFULL

///
/// Set the upper bit to indicate EFI Error.
///
#define ENCODE_ERROR(a) ((RETURN_STATUS)(MAX_BIT | (a)))

#define ENCODE_WARNING(a) ((RETURN_STATUS)(a))
#define RETURN_ERROR(a) (((uint64_t)(RETURN_STATUS)(a)) < 0)

#define RETURN_SUCCESS 0
#define RETURN_LOAD_ERROR ENCODE_ERROR(1)
#define RETURN_INVALID_PARAMETER ENCODE_ERROR(2)
#define RETURN_UNSUPPORTED ENCODE_ERROR(3)
#define RETURN_BAD_BUFFER_SIZE ENCODE_ERROR(4)
#define RETURN_BUFFER_TOO_SMALL ENCODE_ERROR(5)
#define RETURN_NOT_READY ENCODE_ERROR(6)
#define RETURN_DEVICE_ERROR ENCODE_ERROR(7)
#define RETURN_WRITE_PROTECTED ENCODE_ERROR(8)
#define RETURN_OUT_OF_RESOURCES ENCODE_ERROR(9)
#define RETURN_VOLUME_CORRUPTED ENCODE_ERROR(10)
#define RETURN_VOLUME_FULL ENCODE_ERROR(11)
#define RETURN_NO_MEDIA ENCODE_ERROR(12)
#define RETURN_MEDIA_CHANGED ENCODE_ERROR(13)
#define RETURN_NOT_FOUND ENCODE_ERROR(14)
#define RETURN_ACCESS_DENIED ENCODE_ERROR(15)
#define RETURN_NO_RESPONSE ENCODE_ERROR(16)
#define RETURN_NO_MAPPING ENCODE_ERROR(17)
#define RETURN_TIMEOUT ENCODE_ERROR(18)
#define RETURN_NOT_STARTED ENCODE_ERROR(19)
#define RETURN_ALREADY_STARTED ENCODE_ERROR(20)
#define RETURN_ABORTED ENCODE_ERROR(21)
#define RETURN_ICMP_ERROR ENCODE_ERROR(22)
#define RETURN_TFTP_ERROR ENCODE_ERROR(23)
#define RETURN_PROTOCOL_ERROR ENCODE_ERROR(24)
#define RETURN_INCOMPATIBLE_VERSION ENCODE_ERROR(25)
#define RETURN_SECURITY_VIOLATION ENCODE_ERROR(26)
#define RETURN_CRC_ERROR ENCODE_ERROR(27)
#define RETURN_END_OF_MEDIA ENCODE_ERROR(28)
#define RETURN_END_OF_FILE ENCODE_ERROR(31)

#define RETURN_WARN_UNKNOWN_GLYPH ENCODE_WARNING(1)
#define RETURN_WARN_DELETE_FAILURE ENCODE_WARNING(2)
#define RETURN_WARN_WRITE_FAILURE ENCODE_WARNING(3)
#define RETURN_WARN_BUFFER_TOO_SMALL ENCODE_WARNING(4)

//
// Enumeration of EFI_STATUS.
//
#define EFI_SUCCESS RETURN_SUCCESS
#define EFI_LOAD_ERROR RETURN_LOAD_ERROR
#define EFI_INVALID_PARAMETER RETURN_INVALID_PARAMETER
#define EFI_UNSUPPORTED RETURN_UNSUPPORTED
#define EFI_BAD_BUFFER_SIZE RETURN_BAD_BUFFER_SIZE
#define EFI_BUFFER_TOO_SMALL RETURN_BUFFER_TOO_SMALL
#define EFI_NOT_READY RETURN_NOT_READY
#define EFI_DEVICE_ERROR RETURN_DEVICE_ERROR
#define EFI_WRITE_PROTECTED RETURN_WRITE_PROTECTED
#define EFI_OUT_OF_RESOURCES RETURN_OUT_OF_RESOURCES
#define EFI_VOLUME_CORRUPTED RETURN_VOLUME_CORRUPTED
#define EFI_VOLUME_FULL RETURN_VOLUME_FULL
#define EFI_NO_MEDIA RETURN_NO_MEDIA
#define EFI_MEDIA_CHANGED RETURN_MEDIA_CHANGED
#define EFI_NOT_FOUND RETURN_NOT_FOUND
#define EFI_ACCESS_DENIED RETURN_ACCESS_DENIED
#define EFI_NO_RESPONSE RETURN_NO_RESPONSE
#define EFI_NO_MAPPING RETURN_NO_MAPPING
#define EFI_TIMEOUT RETURN_TIMEOUT
#define EFI_NOT_STARTED RETURN_NOT_STARTED
#define EFI_ALREADY_STARTED RETURN_ALREADY_STARTED
#define EFI_ABORTED RETURN_ABORTED
#define EFI_ICMP_ERROR RETURN_ICMP_ERROR
#define EFI_TFTP_ERROR RETURN_TFTP_ERROR
#define EFI_PROTOCOL_ERROR RETURN_PROTOCOL_ERROR
#define EFI_INCOMPATIBLE_VERSION RETURN_INCOMPATIBLE_VERSION
#define EFI_SECURITY_VIOLATION RETURN_SECURITY_VIOLATION
#define EFI_CRC_ERROR RETURN_CRC_ERROR
#define EFI_END_OF_MEDIA RETURN_END_OF_MEDIA
#define EFI_END_OF_FILE RETURN_END_OF_FILE

#define EFI_WARN_UNKNOWN_GLYPH RETURN_WARN_UNKNOWN_GLYPH
#define EFI_WARN_DELETE_FAILURE RETURN_WARN_DELETE_FAILURE
#define EFI_WARN_WRITE_FAILURE RETURN_WARN_WRITE_FAILURE
#define EFI_WARN_BUFFER_TOO_SMALL RETURN_WARN_BUFFER_TOO_SMALL

//
// _WIN_CERTIFICATE.wCertificateType
//
#define WIN_CERT_TYPE_EFI_PKCS115 0x0EF0
#define WIN_CERT_TYPE_EFI_GUID 0x0EF1

//
// EFI Time Abstraction:
//  Year:       2000 - 20XX
//  Month:      1 - 12
//  Day:        1 - 31
//  Hour:       0 - 23
//  Minute:     0 - 59
//  Second:     0 - 59
//  Nanosecond: 0 - 999,999,999
//  TimeZone:   -1440 to 1440 or 2047
//
typedef struct {
    uint16_t Year;
    uint8_t Month;
    uint8_t Day;
    uint8_t Hour;
    uint8_t Minute;
    uint8_t Second;
    uint8_t Pad1;
    uint32_t Nanosecond;
    uint16_t TimeZone;
    uint8_t Daylight;
    uint8_t Pad2;
} EFI_TIME;

typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} EFI_GUID;

typedef uint64_t RETURN_STATUS;
#define EFI_ERROR(A) (A != EFI_SUCCESS)

#define EFI_MAX_BIT 0x8000000000000000UL
#define EFIERR(a) (EFI_MAX_BIT | (a))

typedef uint64_t EFI_STATUS;

///
/// Attributes of variable.
///
#define EFI_VARIABLE_NON_VOLATILE 0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS 0x00000004
///
/// This attribute is identified by the mnemonic 'HR'
/// elsewhere in this specification.
///
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD 0x00000008
///
/// Attributes of Authenticated Variable
///
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define EFI_VARIABLE_APPEND_WRITE 0x00000040
///
/// NOTE: EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS is deprecated and should be considered reserved.
///
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 0x00000010

typedef enum command {
    COMMAND_GET_VARIABLE,
    COMMAND_SET_VARIABLE,
    COMMAND_GET_NEXT_VARIABLE,
    COMMAND_QUERY_VARIABLE_INFO,
    COMMAND_NOTIFY_SB_FAILURE,
} command_t;

typedef struct _WIN_CERTIFICATE {
    uint32_t dwLength;
    uint16_t wRevision;
    uint16_t wCertificateType;
    //UINT8 bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE;

//
// WIN_CERTIFICATE_UEFI_GUID.CertData
//
typedef struct _EFI_CERT_BLOCK_RSA_2048_SHA256 {
    EFI_GUID HashType;
    UINT8 PublicKey[256];
    UINT8 Signature[256];
} EFI_CERT_BLOCK_RSA_2048_SHA256;

typedef struct _WIN_CERTIFICATE_UEFI_GUID {
    WIN_CERTIFICATE Hdr;
    EFI_GUID CertType;

    /* 
   * This is just used as a reference point for the OFFSET_OF macro for finding
   * the payload.
   *
   * I don't really like this, but it's done this way in OVMF so I'm keeping
   * it the same here.
   */
    uint8_t CertData[1];
} WIN_CERTIFICATE_UEFI_GUID;

///
/// AuthInfo is a WIN_CERTIFICATE using the wCertificateType
/// WIN_CERTIFICATE_UEFI_GUID and the CertType
/// EFI_CERT_TYPE_RSA2048_SHA256_GUID. If the attribute specifies
/// authenticated access, then the Data buffer should begin with an
/// authentication descriptor prior to the data payload and DataSize
/// should reflect the the data.and descriptor size. The caller
/// shall digest the Monotonic Count value and the associated data
/// for the variable update using the SHA-256 1-way hash algorithm.
/// The ensuing the 32-byte digest will be signed using the private
/// key associated w/ the public/private 2048-bit RSA key-pair. The
/// WIN_CERTIFICATE shall be used to describe the signature of the
/// Variable data *Data. In addition, the signature will also
/// include the MonotonicCount value to guard against replay attacks.
///
typedef struct {
    ///
    /// Included in the signature of
    /// AuthInfo.Used to ensure freshness/no
    /// replay. Incremented during each
    /// "Write" access.
    ///
    uint64_t MonotonicCount;
    ///
    /// Provides the authorization for the variable
    /// access. It is a signature across the
    /// variable data and the  Monotonic Count
    /// value. Caller uses Private key that is
    /// associated with a public key that has been
    /// provisioned via the key exchange.
    ///
    WIN_CERTIFICATE_UEFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION;

///
/// When the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is
/// set, then the Data buffer shall begin with an instance of a complete (and serialized)
/// EFI_VARIABLE_AUTHENTICATION_2 descriptor. The descriptor shall be followed by the new
/// variable value and DataSize shall reflect the combined size of the descriptor and the new
/// variable value. The authentication descriptor is not part of the variable data and is not
/// returned by subsequent calls to GetVariable().
///
typedef struct {
    ///
    /// For the TimeStamp value, components Pad1, Nanosecond, TimeZone, Daylight and
    /// Pad2 shall be set to 0. This means that the time shall always be expressed in GMT.
    ///
    EFI_TIME TimeStamp;
    ///
    /// Only a CertType of  EFI_CERT_TYPE_PKCS7_GUID is accepted.
    ///
    WIN_CERTIFICATE_UEFI_GUID AuthInfo;
} EFI_VARIABLE_AUTHENTICATION_2;

typedef struct {
    UTF16 *VariableName;
    EFI_GUID *VendorGuid;
    uint32_t Attributes;
    uint64_t DataSize;
    void *Data;
    uint32_t PubKeyIndex;
    uint64_t MonotonicCount;
    EFI_TIME *TimeStamp;
} AUTH_VARIABLE_INFO;

typedef enum {
    AUTH_VAR_TYPE_PK,
    AUTH_VAR_TYPE_KEK,
    AUTH_VAR_TYPE_PRIV,
    AUTH_VAR_TYPE_PAYLOAD,
} AUTH_VAR_TYPE;

typedef AUTH_VAR_TYPE auth_var_t;

///
///  "certdb" variable stores the signer's certificates for non PK/KEK/DB/DBX
/// variables with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS|EFI_VARIABLE_NON_VOLATILE set.
///  "certdbv" variable stores the signer's certificates for non PK/KEK/DB/DBX
/// variables with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set
///
/// GUID: gEfiCertDbGuid
///
/// We need maintain atomicity.
///
/// Format:
/// +----------------------------+
/// | UINT32                     | <-- CertDbListSize, including this UINT32
/// +----------------------------+
/// | AUTH_CERT_DB_DATA          | <-- First CERT
/// +----------------------------+
/// | ........                   |
/// +----------------------------+
/// | AUTH_CERT_DB_DATA          | <-- Last CERT
/// +----------------------------+
///
#define EFI_CERT_DB_NAME L"certdb"
#define EFI_CERT_DB_VOLATILE_NAME L"certdbv"

#pragma pack(1)
typedef struct {
    EFI_GUID VendorGuid;
    uint32_t CertNodeSize;
    uint32_t NameSize;
    uint32_t CertDataSize;
    /// CHAR16  VariableName[NameSize];
    /// UINT8   CertData[CertDataSize];
} AUTH_CERT_DB_DATA;
#pragma pack()

#pragma pack(1)

typedef struct {
    uint32_t CertDataLength; // The length in bytes of X.509 certificate.
    uint8_t CertDataBuffer[0]; // The X.509 certificate content (DER).
} EFI_CERT_DATA;

typedef struct {
    uint8_t CertNumber; // Number of X.509 certificate.
    //EFI_CERT_DATA   CertArray[];  // An array of X.509 certificate.
} EFI_CERT_STACK;

#pragma pack()

extern UTF16 KEK[];
extern UTF16 PK[];
extern UTF16 CERT_DB[];
extern UTF16 CERT_DBV[];
extern UTF16 VENDOR_KEYS[];
extern UTF16 VENDOR_KEYS_NV[];
#define VENDOR_KEYS_VALID 1
#define VENDOR_KEYS_MODIFIED 0

extern UTF16 SECURE_BOOT_ENABLE[];
#define SECURE_BOOT_ENABLE 1
#define SECURE_BOOT_DISABLE 0

#define SHA256_DIGEST_SIZE 32

/*
 *  Size of AuthInfo prior to the data payload.
 */
#define AUTHINFO_SIZE                                                          \
    ((OFFSET_OF(EFI_VARIABLE_AUTHENTICATION, AuthInfo)) +                      \
     (OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData)) +                        \
     sizeof(EFI_CERT_BLOCK_RSA_2048_SHA256))

#define AUTHINFO2_SIZE(VarAuth2)                                               \
    ((OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo)) +                    \
     (UINTN)((EFI_VARIABLE_AUTHENTICATION_2 *)(VarAuth2))                      \
             ->AuthInfo.Hdr.dwLength)

#define OFFSET_OF_AUTHINFO2_CERT_DATA                                          \
    ((OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo)) +                    \
     (OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData)))

#define TWO_BYTE_ENCODE 0x82

///
/// Struct to record signature requirement defined by UEFI spec.
/// For SigHeaderSize and SigDataSize, ((UINT32) ~0) means NO exact length requirement for this field.
///
typedef struct {
    EFI_GUID SigType;
    // Expected SignatureHeader size in Bytes.
    UINT32 SigHeaderSize;
    // Expected SignatureData size in Bytes.
    UINT32 SigDataSize;
} EFI_SIGNATURE_ITEM;

///
/// Variable Attribute combinations.
///
#define VARIABLE_ATTRIBUTE_NV_BS        (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define VARIABLE_ATTRIBUTE_BS_RT        (EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)
#define VARIABLE_ATTRIBUTE_BS_RT_AT     (VARIABLE_ATTRIBUTE_BS_RT | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
#define VARIABLE_ATTRIBUTE_NV_BS_RT     (VARIABLE_ATTRIBUTE_BS_RT | EFI_VARIABLE_NON_VOLATILE)
#define VARIABLE_ATTRIBUTE_NV_BS_RT_HR  (VARIABLE_ATTRIBUTE_NV_BS_RT | EFI_VARIABLE_HARDWARE_ERROR_RECORD)
#define VARIABLE_ATTRIBUTE_NV_BS_RT_AT  (VARIABLE_ATTRIBUTE_NV_BS_RT | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
#define VARIABLE_ATTRIBUTE_AT           EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
#define VARIABLE_ATTRIBUTE_NV_BS_RT_HR_AT    (VARIABLE_ATTRIBUTE_NV_BS_RT_HR | VARIABLE_ATTRIBUTE_AT)
///
/// EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS is deprecated and should be considered as reserved
///
#define VARIABLE_ATTRIBUTE_AT_AW        (EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS)
#define VARIABLE_ATTRIBUTE_NV_BS_RT_AW  (VARIABLE_ATTRIBUTE_NV_BS_RT | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS)
#define VARIABLE_ATTRIBUTE_NV_BS_RT_HR_AT_AW    (VARIABLE_ATTRIBUTE_NV_BS_RT_HR | VARIABLE_ATTRIBUTE_AT_AW)

#endif // __H_UEFITYPES_
