/** @file
  SHA-256 Digest Wrapper Implementation over OpenSSL.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "CryptSha256.h"
#include "uefitypes.h"
#include <stdbool.h>
#include <openssl/sha.h>

/**
  Retrieves the size, in bytes, of the context buffer required for SHA-256 hash operations.

  @return  The size, in bytes, of the context buffer required for SHA-256 hash operations.

**/
UINTN
Sha256GetContextSize (
  VOID
  )
{
  //
  // Retrieves OpenSSL SHA-256 Context Size
  //
  return (UINTN) (sizeof (SHA256_CTX));
}

/**
  Initializes user-supplied memory pointed by Sha256Context as SHA-256 hash context for
  subsequent use.

  If Sha256Context is NULL, then return false.

  @param[out]  Sha256Context  Pointer to SHA-256 context being initialized.

  @retval true   SHA-256 context initialization succeeded.
  @retval false  SHA-256 context initialization failed.

**/
BOOLEAN
Sha256Init (
  OUT  VOID  *Sha256Context
  )
{
  //
  // Check input parameters.
  //
  if (Sha256Context == NULL) {
    return false;
  }

  //
  // OpenSSL SHA-256 Context Initialization
  //
  return (BOOLEAN) (SHA256_Init ((SHA256_CTX *) Sha256Context));
}

/**
  Makes a copy of an existing SHA-256 context.

  If Sha256Context is NULL, then return false.
  If NewSha256Context is NULL, then return false.

  @param[in]  Sha256Context     Pointer to SHA-256 context being copied.
  @param[out] NewSha256Context  Pointer to new SHA-256 context.

  @retval true   SHA-256 context copy succeeded.
  @retval false  SHA-256 context copy failed.

**/
BOOLEAN
Sha256Duplicate (
  IN   CONST VOID  *Sha256Context,
  OUT  VOID        *NewSha256Context
  )
{
  //
  // Check input parameters.
  //
  if (Sha256Context == NULL || NewSha256Context == NULL) {
    return false;
  }

  memcpy (NewSha256Context, Sha256Context, sizeof (SHA256_CTX));

  return true;
}

/**
  Digests the input data and updates SHA-256 context.

  This function performs SHA-256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-256 context should be already correctly initialized by Sha256Init(), and should not be finalized
  by Sha256Final(). Behavior with invalid context is undefined.

  If Sha256Context is NULL, then return false.

  @param[in, out]  Sha256Context  Pointer to the SHA-256 context.
  @param[in]       Data           Pointer to the buffer containing the data to be hashed.
  @param[in]       DataSize       Size of Data buffer in bytes.

  @retval true   SHA-256 data digest succeeded.
  @retval false  SHA-256 data digest failed.

**/
BOOLEAN
Sha256Update (
  IN OUT  VOID        *Sha256Context,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{
  //
  // Check input parameters.
  //
  if (Sha256Context == NULL) {
    return false;
  }

  //
  // Check invalid parameters, in case that only DataLength was checked in OpenSSL
  //
  if (Data == NULL && DataSize != 0) {
    return false;
  }

  //
  // OpenSSL SHA-256 Hash Update
  //
  return (BOOLEAN) (SHA256_Update ((SHA256_CTX *) Sha256Context, Data, DataSize));
}

/**
  Completes computation of the SHA-256 digest value.

  This function completes SHA-256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-256 context cannot
  be used again.
  SHA-256 context should be already correctly initialized by Sha256Init(), and should not be
  finalized by Sha256Final(). Behavior with invalid SHA-256 context is undefined.

  If Sha256Context is NULL, then return false.
  If HashValue is NULL, then return false.

  @param[in, out]  Sha256Context  Pointer to the SHA-256 context.
  @param[out]      HashValue      Pointer to a buffer that receives the SHA-256 digest
                                  value (32 bytes).

  @retval true   SHA-256 digest computation succeeded.
  @retval false  SHA-256 digest computation failed.

**/
BOOLEAN
Sha256Final (
  IN OUT  VOID   *Sha256Context,
  OUT     UINT8  *HashValue
  )
{
  //
  // Check input parameters.
  //
  if (Sha256Context == NULL || HashValue == NULL) {
    return false;
  }

  //
  // OpenSSL SHA-256 Hash Finalization
  //
  return (BOOLEAN) (SHA256_Final (HashValue, (SHA256_CTX *) Sha256Context));
}

/**
  Computes the SHA-256 message digest of a input data buffer.

  This function performs the SHA-256 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return false.

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of Data buffer in bytes.
  @param[out]  HashValue   Pointer to a buffer that receives the SHA-256 digest
                           value (32 bytes).

  @retval true   SHA-256 digest computation succeeded.
  @retval false  SHA-256 digest computation failed.
  @retval false  This interface is not supported.

**/
BOOLEAN
Sha256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  //
  // Check input parameters.
  //
  if (HashValue == NULL) {
    return false;
  }
  if (Data == NULL && DataSize != 0) {
    return false;
  }

  //
  // OpenSSL SHA-256 Hash Computation.
  //
  if (SHA256 (Data, DataSize, HashValue) == NULL) {
    return false;
  } else {
    return true;
  }
}
