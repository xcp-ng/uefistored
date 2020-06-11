#ifndef __H_UEFITYPES_
#define __H_UEFITYPES_

#include <stdint.h>
#include <uchar.h>

typedef uint16_t UTF16;

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

#if 0
typedef struct {
    uint32_t  Data1;
    uint16_t  Data2;
    uint16_t  Data3;
    uint8_t   Data4[8];
} EFI_GUID;
#endif

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

typedef struct {
    uint32_t  data1;
    uint16_t  data2;
    uint16_t  data3;
    uint8_t   data4[8];
} efi_guid_t;


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

#define SECURE_BOOT_MODE_ENABLE           1
#define SECURE_BOOT_MODE_DISABLE          0

#define SETUP_MODE                        1
#define USER_MODE                         0

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

extern const EFI_GUID gEfiCertPkcs7Guid;
extern const EFI_GUID gEfiCertX509Guid;
extern const EFI_GUID gEfiGlobalVariableGuid;

#endif // __H_UEFITYPES_
