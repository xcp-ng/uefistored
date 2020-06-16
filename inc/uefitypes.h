#ifndef __H_UEFITYPES_
#define __H_UEFITYPES_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef char CHAR8;
typedef uint16_t CHAR16;

typedef uint8_t UTF8;
typedef uint16_t UTF16;

typedef uint16_t UINT16;
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef int32_t INT32;
typedef uint64_t UINTN;

typedef bool BOOLEAN;
typedef void VOID;
#define CONST const

#define IN
#define OUT

#define OFFSET_OF(TYPE, Field) ((uint64_t) &(((TYPE *)0)->Field))

//
// Processor specific defines
//
#define MAX_BIT     0x8000000000000000ULL
#define MAX_2_BITS  0xC000000000000000ULL

//
// Maximum legal Itanium-based address
//
#define MAX_ADDRESS   0xFFFFFFFFFFFFFFFFULL

///
/// Set the upper bit to indicate EFI Error.
///
#define ENCODE_ERROR(a)              ((RETURN_STATUS)(MAX_BIT | (a)))

#define ENCODE_WARNING(a)            ((RETURN_STATUS)(a))
#define RETURN_ERROR(a)              (((uint64_t)(RETURN_STATUS)(a)) < 0)

#define RETURN_SUCCESS               0
#define RETURN_LOAD_ERROR            ENCODE_ERROR (1)
#define RETURN_INVALID_PARAMETER     ENCODE_ERROR (2)
#define RETURN_UNSUPPORTED           ENCODE_ERROR (3)
#define RETURN_BAD_BUFFER_SIZE       ENCODE_ERROR (4)
#define RETURN_BUFFER_TOO_SMALL      ENCODE_ERROR (5)
#define RETURN_NOT_READY             ENCODE_ERROR (6)
#define RETURN_DEVICE_ERROR          ENCODE_ERROR (7)
#define RETURN_WRITE_PROTECTED       ENCODE_ERROR (8)
#define RETURN_OUT_OF_RESOURCES      ENCODE_ERROR (9)
#define RETURN_VOLUME_CORRUPTED      ENCODE_ERROR (10)
#define RETURN_VOLUME_FULL           ENCODE_ERROR (11)
#define RETURN_NO_MEDIA              ENCODE_ERROR (12)
#define RETURN_MEDIA_CHANGED         ENCODE_ERROR (13)
#define RETURN_NOT_FOUND             ENCODE_ERROR (14)
#define RETURN_ACCESS_DENIED         ENCODE_ERROR (15)
#define RETURN_NO_RESPONSE           ENCODE_ERROR (16)
#define RETURN_NO_MAPPING            ENCODE_ERROR (17)
#define RETURN_TIMEOUT               ENCODE_ERROR (18)
#define RETURN_NOT_STARTED           ENCODE_ERROR (19)
#define RETURN_ALREADY_STARTED       ENCODE_ERROR (20)
#define RETURN_ABORTED               ENCODE_ERROR (21)
#define RETURN_ICMP_ERROR            ENCODE_ERROR (22)
#define RETURN_TFTP_ERROR            ENCODE_ERROR (23)
#define RETURN_PROTOCOL_ERROR        ENCODE_ERROR (24)
#define RETURN_INCOMPATIBLE_VERSION  ENCODE_ERROR (25)
#define RETURN_SECURITY_VIOLATION    ENCODE_ERROR (26)
#define RETURN_CRC_ERROR             ENCODE_ERROR (27)
#define RETURN_END_OF_MEDIA          ENCODE_ERROR (28)
#define RETURN_END_OF_FILE           ENCODE_ERROR (31)

#define RETURN_WARN_UNKNOWN_GLYPH    ENCODE_WARNING (1)
#define RETURN_WARN_DELETE_FAILURE   ENCODE_WARNING (2)
#define RETURN_WARN_WRITE_FAILURE    ENCODE_WARNING (3)
#define RETURN_WARN_BUFFER_TOO_SMALL ENCODE_WARNING (4)

//
// Enumeration of EFI_STATUS.
// 
#define EFI_SUCCESS               RETURN_SUCCESS              
#define EFI_LOAD_ERROR            RETURN_LOAD_ERROR           
#define EFI_INVALID_PARAMETER     RETURN_INVALID_PARAMETER    
#define EFI_UNSUPPORTED           RETURN_UNSUPPORTED          
#define EFI_BAD_BUFFER_SIZE       RETURN_BAD_BUFFER_SIZE      
#define EFI_BUFFER_TOO_SMALL      RETURN_BUFFER_TOO_SMALL     
#define EFI_NOT_READY             RETURN_NOT_READY            
#define EFI_DEVICE_ERROR          RETURN_DEVICE_ERROR         
#define EFI_WRITE_PROTECTED       RETURN_WRITE_PROTECTED      
#define EFI_OUT_OF_RESOURCES      RETURN_OUT_OF_RESOURCES     
#define EFI_VOLUME_CORRUPTED      RETURN_VOLUME_CORRUPTED     
#define EFI_VOLUME_FULL           RETURN_VOLUME_FULL          
#define EFI_NO_MEDIA              RETURN_NO_MEDIA             
#define EFI_MEDIA_CHANGED         RETURN_MEDIA_CHANGED        
#define EFI_NOT_FOUND             RETURN_NOT_FOUND            
#define EFI_ACCESS_DENIED         RETURN_ACCESS_DENIED        
#define EFI_NO_RESPONSE           RETURN_NO_RESPONSE          
#define EFI_NO_MAPPING            RETURN_NO_MAPPING           
#define EFI_TIMEOUT               RETURN_TIMEOUT              
#define EFI_NOT_STARTED           RETURN_NOT_STARTED          
#define EFI_ALREADY_STARTED       RETURN_ALREADY_STARTED      
#define EFI_ABORTED               RETURN_ABORTED              
#define EFI_ICMP_ERROR            RETURN_ICMP_ERROR           
#define EFI_TFTP_ERROR            RETURN_TFTP_ERROR           
#define EFI_PROTOCOL_ERROR        RETURN_PROTOCOL_ERROR       
#define EFI_INCOMPATIBLE_VERSION  RETURN_INCOMPATIBLE_VERSION 
#define EFI_SECURITY_VIOLATION    RETURN_SECURITY_VIOLATION   
#define EFI_CRC_ERROR             RETURN_CRC_ERROR   
#define EFI_END_OF_MEDIA          RETURN_END_OF_MEDIA
#define EFI_END_OF_FILE           RETURN_END_OF_FILE

#define EFI_WARN_UNKNOWN_GLYPH    RETURN_WARN_UNKNOWN_GLYPH   
#define EFI_WARN_DELETE_FAILURE   RETURN_WARN_DELETE_FAILURE  
#define EFI_WARN_WRITE_FAILURE    RETURN_WARN_WRITE_FAILURE   
#define EFI_WARN_BUFFER_TOO_SMALL RETURN_WARN_BUFFER_TOO_SMALL

//
// _WIN_CERTIFICATE.wCertificateType
// 
#define WIN_CERT_TYPE_EFI_PKCS115   0x0EF0
#define WIN_CERT_TYPE_EFI_GUID      0x0EF1

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
  uint16_t  Year;
  uint8_t   Month;
  uint8_t   Day;
  uint8_t   Hour;
  uint8_t   Minute;
  uint8_t   Second;
  uint8_t   Pad1;
  uint32_t  Nanosecond;
  uint16_t   TimeZone;
  uint8_t   Daylight;
  uint8_t   Pad2;
} EFI_TIME;

typedef struct {
  uint32_t  Data1;
  uint16_t  Data2;
  uint16_t  Data3;
  uint8_t   Data4[8];
} EFI_GUID;

typedef uint64_t RETURN_STATUS;
#define EFI_ERROR(A)              RETURN_ERROR(A)

#define EFI_MAX_BIT       0x8000000000000000UL
#define EFIERR(a)         (EFI_MAX_BIT | (a))

typedef uint64_t EFI_STATUS;
//#define EFI_INVALID_PARAMETER EFIERR(2)
//#define EFI_BUFFER_TOO_SMALL EFIERR(5)
//#define EFI_DEVICE_ERROR EFIERR(7)
//#define EFI_OUT_OF_RESOURCES EFIERR(9)
//#define EFI_NOT_FOUND EFIERR(14)
//#define EFI_SECURITY_VIOLATION EFIERR(26)

///
/// Attributes of variable.
///
#define EFI_VARIABLE_NON_VOLATILE                            0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                      0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS                          0x00000004
///
/// This attribute is identified by the mnemonic 'HR'
/// elsewhere in this specification.
///
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                   0x00000008
///
/// Attributes of Authenticated Variable
///
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS   0x00000020
#define EFI_VARIABLE_APPEND_WRITE                            0x00000040
///
/// NOTE: EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS is deprecated and should be considered reserved.
///
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS              0x00000010

typedef enum command {
    COMMAND_GET_VARIABLE,
    COMMAND_SET_VARIABLE,
    COMMAND_GET_NEXT_VARIABLE,
    COMMAND_QUERY_VARIABLE_INFO,
    COMMAND_NOTIFY_SB_FAILURE,
} command_t;

/**
 * Secure Boot definitions
 */
#define EFI_IMAGE_SECURITY_DATABASE_GUID \
  { \
    0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0xe, 0x67, 0x65, 0x6f } \
  }

///
/// Varialbe name with guid EFI_IMAGE_SECURITY_DATABASE_GUID
/// for the authorized signature database.
///
#define EFI_IMAGE_SECURITY_DATABASE       L"db"
///
/// Varialbe name with guid EFI_IMAGE_SECURITY_DATABASE_GUID
/// for the forbidden signature database.
///
#define EFI_IMAGE_SECURITY_DATABASE1      L"dbx"
///
/// Variable name with guid EFI_IMAGE_SECURITY_DATABASE_GUID
/// for the timestamp signature database.
///
#define EFI_IMAGE_SECURITY_DATABASE2      L"dbt"

//***********************************************************************
// Signature Database
//***********************************************************************
///
/// The format of a signature database.
///
#pragma pack(1)

typedef struct {
  ///
  /// An identifier which identifies the agent which added the signature to the list.
  ///
  EFI_GUID          SignatureOwner;
  ///
  /// The format of the signature is defined by the SignatureType.
  ///
  uint8_t             SignatureData[1];
} EFI_SIGNATURE_DATA;

typedef struct {
  ///
  /// Type of the signature. GUID signature types are defined in below.
  ///
  EFI_GUID            SignatureType;
  ///
  /// Total size of the signature list, including this header.
  ///
  uint32_t              SignatureListSize;
  ///
  /// Size of the signature header which precedes the array of signatures.
  ///
  uint32_t              SignatureHeaderSize;
  ///
  /// Size of each signature.
  ///
  uint32_t              SignatureSize;
  ///
  /// Header before the array of signatures. The format of this header is specified
  /// by the SignatureType.
  /// uint8_t           SignatureHeader[SignatureHeaderSize];
  ///
  /// An array of signatures. Each signature is SignatureSize bytes in length.
  /// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
  ///
} EFI_SIGNATURE_LIST;

typedef struct _WIN_CERTIFICATE {
  uint32_t  dwLength;
  uint16_t  wRevision;
  uint16_t  wCertificateType;
  //UINT8 bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE;

//
// WIN_CERTIFICATE_UEFI_GUID.CertData
// 
typedef struct _EFI_CERT_BLOCK_RSA_2048_SHA256 {
  EFI_GUID  HashType;
  UINT8     PublicKey[256];
  UINT8     Signature[256];
} EFI_CERT_BLOCK_RSA_2048_SHA256;

typedef struct _WIN_CERTIFICATE_UEFI_GUID {
  WIN_CERTIFICATE   Hdr;
  EFI_GUID          CertType;

  /* 
   * This is just used as a reference point for the OFFSET_OF macro for finding
   * the payload.
   *
   * I don't really like this, but it's done this way in OVMF so I'm keeping
   * it the same here.
   */
  uint8_t             CertData[1];
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
  uint64_t                      MonotonicCount;
  ///
  /// Provides the authorization for the variable
  /// access. It is a signature across the
  /// variable data and the  Monotonic Count
  /// value. Caller uses Private key that is
  /// associated with a public key that has been
  /// provisioned via the key exchange.
  ///
  WIN_CERTIFICATE_UEFI_GUID   AuthInfo;
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
  EFI_TIME                    TimeStamp;
  ///
  /// Only a CertType of  EFI_CERT_TYPE_PKCS7_GUID is accepted.
  ///
  WIN_CERTIFICATE_UEFI_GUID   AuthInfo;
 } EFI_VARIABLE_AUTHENTICATION_2;


typedef struct {
    UTF16        *VariableName;
    EFI_GUID      *VendorGuid;
    uint32_t        Attributes;
    uint64_t         DataSize;
    void          *Data;
    uint32_t        PubKeyIndex;
    uint64_t        MonotonicCount;
    EFI_TIME      *TimeStamp;
} AUTH_VARIABLE_INFO;

typedef enum {
    AuthVarTypePk,
    AuthVarTypeKek,
    AuthVarTypePriv,
    AuthVarTypePayload
} AUTHVAR_TYPE; 

typedef AUTHVAR_TYPE auth_var_t;

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
#define EFI_CERT_DB_NAME                 L"certdb"
#define EFI_CERT_DB_VOLATILE_NAME        L"certdbv"

#pragma pack(1)
typedef struct {
  EFI_GUID    VendorGuid;
  uint32_t      CertNodeSize;
  uint32_t      NameSize;
  uint32_t      CertDataSize;
  /// CHAR16  VariableName[NameSize];
  /// UINT8   CertData[CertDataSize];
} AUTH_CERT_DB_DATA;
#pragma pack()

#pragma pack(1)

typedef struct {
    uint32_t    CertDataLength;       // The length in bytes of X.509 certificate.
    uint8_t     CertDataBuffer[0];    // The X.509 certificate content (DER).
} EFI_CERT_DATA;

typedef struct {
    uint8_t             CertNumber;   // Number of X.509 certificate.
    //EFI_CERT_DATA   CertArray[];  // An array of X.509 certificate.
} EFI_CERT_STACK;

#pragma pack()           

extern UTF16 KEK[];
extern UTF16 PK[];
extern UTF16 CERT_DB[];
extern UTF16 CERT_DBV[];
extern UTF16 VENDOR_KEYS[];
extern UTF16 VENDOR_KEYS_NV[];
#define VENDOR_KEYS_VALID             1
#define VENDOR_KEYS_MODIFIED          0

extern UTF16 SECURE_BOOT_ENABLE[];
#define SECURE_BOOT_ENABLE               1
#define SECURE_BOOT_DISABLE              0


#define SHA256_DIGEST_SIZE  32

///
/// Size of AuthInfo prior to the data payload.
///
#define AUTHINFO_SIZE ((OFFSET_OF (EFI_VARIABLE_AUTHENTICATION, AuthInfo)) + \
                       (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)) + \
                       sizeof (EFI_CERT_BLOCK_RSA_2048_SHA256))

#define AUTHINFO2_SIZE(VarAuth2) ((OFFSET_OF (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo)) + \
                                  (UINTN) ((EFI_VARIABLE_AUTHENTICATION_2 *) (VarAuth2))->AuthInfo.Hdr.dwLength)

#define OFFSET_OF_AUTHINFO2_CERT_DATA ((OFFSET_OF (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo)) + \
                                       (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)))

#define TWO_BYTE_ENCODE 0x82


///
/// Struct to record signature requirement defined by UEFI spec.
/// For SigHeaderSize and SigDataSize, ((UINT32) ~0) means NO exact length requirement for this field.
///
typedef struct {
  EFI_GUID    SigType;
  // Expected SignatureHeader size in Bytes.
  UINT32      SigHeaderSize;
  // Expected SignatureData size in Bytes.
  UINT32      SigDataSize;
} EFI_SIGNATURE_ITEM;

///
/// This identifies a signature containing a SHA-256 hash. The SignatureHeader size shall
/// always be 0. The SignatureSize shall always be 16 (size of SignatureOwner component) +
/// 32 bytes.
///
#define EFI_CERT_SHA256_GUID \
  { \
    0xc1c41626, 0x504c, 0x4092, {0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28} \
  }

///
/// This identifies a signature containing an RSA-2048 key. The key (only the modulus
/// since the public key exponent is known to be 0x10001) shall be stored in big-endian
/// order.
/// The SignatureHeader size shall always be 0. The SignatureSize shall always be 16 (size
/// of SignatureOwner component) + 256 bytes.
///
#define EFI_CERT_RSA2048_GUID \
  { \
    0x3c5766e8, 0x269c, 0x4e34, {0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6} \
  }

///
/// This identifies a signature containing a RSA-2048 signature of a SHA-256 hash.  The
/// SignatureHeader size shall always be 0. The SignatureSize shall always be 16 (size of
/// SignatureOwner component) + 256 bytes.
///
#define EFI_CERT_RSA2048_SHA256_GUID \
  { \
    0xe2b36190, 0x879b, 0x4a3d, {0xad, 0x8d, 0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84} \
  }

///
/// This identifies a signature containing a SHA-1 hash.  The SignatureSize shall always
/// be 16 (size of SignatureOwner component) + 20 bytes.
///
#define EFI_CERT_SHA1_GUID \
  { \
    0x826ca512, 0xcf10, 0x4ac9, {0xb1, 0x87, 0xbe, 0x1, 0x49, 0x66, 0x31, 0xbd} \
  }

///
/// TThis identifies a signature containing a RSA-2048 signature of a SHA-1 hash.  The
/// SignatureHeader size shall always be 0. The SignatureSize shall always be 16 (size of
/// SignatureOwner component) + 256 bytes.
///
#define EFI_CERT_RSA2048_SHA1_GUID \
  { \
    0x67f8444f, 0x8743, 0x48f1, {0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80} \
  }

///
/// This identifies a signature based on an X.509 certificate. If the signature is an X.509
/// certificate then verification of the signature of an image should validate the public
/// key certificate in the image using certificate path verification, up to this X.509
/// certificate as a trusted root.  The SignatureHeader size shall always be 0. The
/// SignatureSize may vary but shall always be 16 (size of the SignatureOwner component) +
/// the size of the certificate itself.
/// Note: This means that each certificate will normally be in a separate EFI_SIGNATURE_LIST.
///
#define EFI_CERT_X509_GUID \
  { \
    0xa5c059a1, 0x94e4, 0x4aa7, {0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72} \
  }

///
/// This identifies a signature containing a SHA-224 hash. The SignatureHeader size shall
/// always be 0. The SignatureSize shall always be 16 (size of SignatureOwner component) +
/// 28 bytes.
///
#define EFI_CERT_SHA224_GUID \
  { \
    0xb6e5233, 0xa65c, 0x44c9, {0x94, 0x7, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd} \
  }

///
/// This identifies a signature containing a SHA-384 hash. The SignatureHeader size shall
/// always be 0. The SignatureSize shall always be 16 (size of SignatureOwner component) +
/// 48 bytes.
///
#define EFI_CERT_SHA384_GUID \
  { \
    0xff3e5307, 0x9fd0, 0x48c9, {0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x1} \
  }

///
/// This identifies a signature containing a SHA-512 hash. The SignatureHeader size shall
/// always be 0. The SignatureSize shall always be 16 (size of SignatureOwner component) +
/// 64 bytes.
///
#define EFI_CERT_SHA512_GUID \
  { \
    0x93e0fae, 0xa6c4, 0x4f50, {0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a} \
  }

///
/// This identifies a signature containing the SHA256 hash of an X.509 certificate's
/// To-Be-Signed contents, and a time of revocation. The SignatureHeader size shall
/// always be 0. The SignatureSize shall always be 16 (size of the SignatureOwner component)
/// + 48 bytes for an EFI_CERT_X509_SHA256 structure. If the TimeOfRevocation is non-zero,
/// the certificate should be considered to be revoked from that time and onwards, and
/// otherwise the certificate shall be considered to always be revoked.
///
#define EFI_CERT_X509_SHA256_GUID \
  { \
    0x3bd2a492, 0x96c0, 0x4079, {0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed } \
  }

///
/// This identifies a signature containing the SHA384 hash of an X.509 certificate's
/// To-Be-Signed contents, and a time of revocation. The SignatureHeader size shall
/// always be 0. The SignatureSize shall always be 16 (size of the SignatureOwner component)
/// + 64 bytes for an EFI_CERT_X509_SHA384 structure. If the TimeOfRevocation is non-zero,
/// the certificate should be considered to be revoked from that time and onwards, and
/// otherwise the certificate shall be considered to always be revoked.
///
#define EFI_CERT_X509_SHA384_GUID \
  { \
    0x7076876e, 0x80c2, 0x4ee6, {0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b } \
  }

///
/// This identifies a signature containing the SHA512 hash of an X.509 certificate's
/// To-Be-Signed contents, and a time of revocation. The SignatureHeader size shall
/// always be 0. The SignatureSize shall always be 16 (size of the SignatureOwner component)
/// + 80 bytes for an EFI_CERT_X509_SHA512 structure. If the TimeOfRevocation is non-zero,
/// the certificate should be considered to be revoked from that time and onwards, and
/// otherwise the certificate shall be considered to always be revoked.
///
#define EFI_CERT_X509_SHA512_GUID \
  { \
    0x446dbf63, 0x2502, 0x4cda, {0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d } \
  }

///
/// This identifies a signature containing a DER-encoded PKCS #7 version 1.5 [RFC2315]
/// SignedData value.
///
#define EFI_CERT_TYPE_PKCS7_GUID \
  { \
    0x4aafd29d, 0x68df, 0x49ee, {0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7} \
  }


static inline bool CompareGuid(EFI_GUID *a, EFI_GUID *b)
{
    return memcmp(a, b, sizeof(EFI_GUID)) == 0;
}

static inline void WriteUnaligned32(uint32_t *dest, uint32_t val)
{
    memcpy(dest, &val, sizeof(*dest));
}

static inline uint32_t ReadUnaligned32(uint32_t *src)
{
    uint32_t val;

    memcpy(&val, src, sizeof(val));

    return val;
}

static inline bool UserPhysicalPresent(void)
{
    /* Always True for OVMF */
    return true;
}

#endif // __H_UEFITYPES_
