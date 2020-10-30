/** 
 * Tests spec conformance with UEFI authenticated variables.
 *
 * Modified from EDK2's SCT tests.
 */

#include <stdint.h>

#include "munit/munit.h"

#include "uefi/authlib.h"
#include "uefi/types.h"
#include "storage.h"
#include "test_common.h"

static uint8_t invalid_der[] = {
    0xdc, 0x07, 0x07, 0x02, 0x10, 0x38, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0f, 0x03, 0x00, 0x00, 0x00, 0x02, 0xf1, 0x0e,
    0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d,
    0x37, 0x56, 0x65, 0xa7, 0x30, 0x82, 0x02, 0xf3, 0x02, 0x01, 0x01, 0x31,
    0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x05, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x01, 0xfa, 0x30, 0x82, 0x01,
    0xf6, 0x30, 0x82, 0x01, 0x5f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,
    0x68, 0x99, 0x65, 0xc8, 0xe3, 0xb6, 0xbd, 0x81, 0x45, 0x85, 0x00, 0x61,
    0x17, 0x34, 0x2e, 0xde, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x30, 0x14, 0x31, 0x12, 0x30,
    0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x54, 0x65, 0x73, 0x74,
    0x52, 0x6f, 0x6f, 0x74, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x32, 0x30,
    0x37, 0x30, 0x32, 0x30, 0x37, 0x33, 0x32, 0x32, 0x37, 0x5a, 0x17, 0x0d,
    0x33, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
    0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x09, 0x54, 0x65, 0x73, 0x74, 0x52, 0x6f, 0x6f, 0x74, 0x31, 0x30,
    0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89,
    0x02, 0x81, 0x81, 0x00, 0xb5, 0x5b, 0x04, 0xe6, 0x76, 0x84, 0x46, 0xc4,
    0x81, 0x1f, 0x97, 0x1c, 0x10, 0x0c, 0x3e, 0x7f, 0xf8, 0x56, 0xe7, 0x7a,
    0x6d, 0xac, 0x37, 0x8c, 0x24, 0x98, 0x8f, 0xf0, 0xfd, 0xdf, 0x44, 0x90,
    0x8c, 0xe0, 0x29, 0x84, 0x23, 0xf6, 0x00, 0x9e, 0x39, 0x0d, 0x2e, 0x81,
    0x86, 0xff, 0x52, 0x11, 0xdb, 0x75, 0x3f, 0x12, 0xc5, 0x5e, 0xb2, 0x8e,
    0x12, 0x12, 0x1a, 0x80, 0x37, 0xbd, 0x31, 0xe0, 0x87, 0x5c, 0x13, 0x48,
    0x3a, 0xf2, 0x55, 0x37, 0x3b, 0x72, 0x8b, 0xc0, 0x78, 0xa4, 0x60, 0x2f,
    0xaf, 0xf2, 0x0e, 0xc9, 0x03, 0xd6, 0x90, 0x01, 0x81, 0xf1, 0xda, 0xc3,
    0x6e, 0x88, 0xbe, 0x12, 0x21, 0x0c, 0x6f, 0x62, 0x75, 0x43, 0xa8, 0xc6,
    0xd1, 0x40, 0x62, 0x96, 0xf8, 0x1e, 0xa3, 0x5d, 0x9f, 0xf7, 0xdb, 0x8e,
    0xba, 0x78, 0x4d, 0xef, 0x58, 0x5c, 0x93, 0x2d, 0x15, 0x25, 0x39, 0x1d,
    0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x49, 0x30, 0x47, 0x30, 0x45, 0x06,
    0x03, 0x55, 0x1d, 0x01, 0x04, 0x3e, 0x30, 0x3c, 0x80, 0x10, 0xec, 0xd2,
    0x82, 0xce, 0x3b, 0x12, 0xd2, 0xef, 0x3f, 0xc8, 0x8d, 0x9c, 0xb9, 0x07,
    0x7d, 0x56, 0xa1, 0x16, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x13, 0x09, 0x54, 0x65, 0x73, 0x74, 0x52, 0x6f, 0x6f,
    0x74, 0x31, 0x82, 0x10, 0x68, 0x99, 0x65, 0xc8, 0xe3, 0xb6, 0xbd, 0x81,
    0x45, 0x85, 0x00, 0x61, 0x17, 0x34, 0x2e, 0xde, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x03,
    0x81, 0x81, 0x00, 0x48, 0x97, 0xd6, 0xad, 0x9d, 0xa3, 0x9c, 0x45, 0xfc,
    0xd6, 0x82, 0x51, 0x06, 0x94, 0xfc, 0x3f, 0xed, 0x8d, 0xab, 0xcd, 0x87,
    0x9c, 0x80, 0x22, 0x30, 0x14, 0x27, 0xc7, 0x89, 0x04, 0x08, 0x2c, 0x51,
    0x68, 0x6a, 0xf5, 0x19, 0x6a, 0x57, 0x77, 0x4e, 0xc6, 0x55, 0xbf, 0xaa,
    0x05, 0x42, 0xaa, 0xbf, 0xf8, 0x4d, 0xc5, 0x03, 0x97, 0x65, 0x67, 0xca,
    0x52, 0xd3, 0xa7, 0x61, 0xb1, 0x01, 0xac, 0xdd, 0x4e, 0xc1, 0x96, 0x70,
    0xe4, 0xf5, 0xe0, 0x99, 0x28, 0xf5, 0xa0, 0xcf, 0xb2, 0x9e, 0x23, 0x00,
    0xf0, 0xd2, 0x18, 0x73, 0x30, 0xbb, 0xe4, 0x33, 0xdb, 0x3e, 0xd3, 0x4e,
    0x4e, 0x56, 0x12, 0x36, 0x21, 0x28, 0x5d, 0x3b, 0x43, 0xe1, 0xf3, 0x9a,
    0xd1, 0x2d, 0xad, 0x31, 0xfb, 0x40, 0x9b, 0x57, 0xb2, 0xb5, 0x9f, 0x6e,
    0x8e, 0x39, 0xff, 0x57, 0x20, 0xd2, 0x44, 0xb8, 0xa3, 0x49, 0xfb, 0x31,
    0x81, 0xd1, 0x30, 0x81, 0xce, 0x02, 0x01, 0x01, 0x30, 0x28, 0x30, 0x14,
    0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x54,
    0x65, 0x73, 0x74, 0x52, 0x6f, 0x6f, 0x74, 0x31, 0x02, 0x10, 0x68, 0x99,
    0x65, 0xc8, 0xe3, 0xb6, 0xbd, 0x81, 0x45, 0x85, 0x00, 0x61, 0x17, 0x34,
    0x2e, 0xde, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x81, 0x80, 0xa2,
    0x86, 0x53, 0xe2, 0xf2, 0x84, 0xd3, 0xe1, 0x75, 0x5d, 0xa4, 0x45, 0xf7,
    0xd7, 0x9e, 0x78, 0x23, 0x14, 0x62, 0x4f, 0x4e, 0xf9, 0x02, 0xf0, 0x8c,
    0xfb, 0x9b, 0x44, 0x9e, 0x13, 0x1c, 0x7d, 0x09, 0x13, 0x33, 0xc4, 0x18,
    0x65, 0x1a, 0x7e, 0xc1, 0x8b, 0xdf, 0x61, 0x8c, 0xda, 0x74, 0x66, 0x81,
    0x40, 0xd0, 0x3f, 0x76, 0x41, 0x28, 0x75, 0xdd, 0x0e, 0xaa, 0x10, 0xee,
    0x2c, 0x41, 0x4b, 0x70, 0x51, 0xb5, 0xab, 0x06, 0x35, 0x26, 0x80, 0xcf,
    0x73, 0xc8, 0x07, 0x4a, 0x31, 0xe6, 0x2b, 0xb6, 0xba, 0xe2, 0x19, 0x0f,
    0x46, 0xd7, 0x5c, 0xb9, 0xc7, 0xea, 0x2b, 0xc9, 0x05, 0x0b, 0x35, 0xf1,
    0x27, 0x5d, 0xd1, 0xaf, 0x27, 0x33, 0x08, 0xfa, 0xee, 0x4e, 0x7b, 0x64,
    0x01, 0x8e, 0x82, 0xb5, 0x68, 0xb3, 0xd7, 0x1a, 0x54, 0x89, 0x68, 0xb9,
    0x7c, 0x85, 0x9e, 0x58, 0xc4, 0xf4, 0x98, 0x30, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38, 0x38 //change the last 0x39 to 0x38
};

static uint8_t valid_der[] = {
    0xdc, 0x07, 0x07, 0x04, 0x09, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0f, 0x03, 0x00, 0x00, 0x00, 0x02, 0xf1, 0x0e,
    0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d,
    0x37, 0x56, 0x65, 0xa7, 0x30, 0x82, 0x02, 0xf3, 0x02, 0x01, 0x01, 0x31,
    0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x05, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x01, 0xfa, 0x30, 0x82, 0x01,
    0xf6, 0x30, 0x82, 0x01, 0x5f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,
    0x68, 0x99, 0x65, 0xc8, 0xe3, 0xb6, 0xbd, 0x81, 0x45, 0x85, 0x00, 0x61,
    0x17, 0x34, 0x2e, 0xde, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x30, 0x14, 0x31, 0x12, 0x30,
    0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x54, 0x65, 0x73, 0x74,
    0x52, 0x6f, 0x6f, 0x74, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x32, 0x30,
    0x37, 0x30, 0x32, 0x30, 0x37, 0x33, 0x32, 0x32, 0x37, 0x5a, 0x17, 0x0d,
    0x33, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
    0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x09, 0x54, 0x65, 0x73, 0x74, 0x52, 0x6f, 0x6f, 0x74, 0x31, 0x30,
    0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89,
    0x02, 0x81, 0x81, 0x00, 0xb5, 0x5b, 0x04, 0xe6, 0x76, 0x84, 0x46, 0xc4,
    0x81, 0x1f, 0x97, 0x1c, 0x10, 0x0c, 0x3e, 0x7f, 0xf8, 0x56, 0xe7, 0x7a,
    0x6d, 0xac, 0x37, 0x8c, 0x24, 0x98, 0x8f, 0xf0, 0xfd, 0xdf, 0x44, 0x90,
    0x8c, 0xe0, 0x29, 0x84, 0x23, 0xf6, 0x00, 0x9e, 0x39, 0x0d, 0x2e, 0x81,
    0x86, 0xff, 0x52, 0x11, 0xdb, 0x75, 0x3f, 0x12, 0xc5, 0x5e, 0xb2, 0x8e,
    0x12, 0x12, 0x1a, 0x80, 0x37, 0xbd, 0x31, 0xe0, 0x87, 0x5c, 0x13, 0x48,
    0x3a, 0xf2, 0x55, 0x37, 0x3b, 0x72, 0x8b, 0xc0, 0x78, 0xa4, 0x60, 0x2f,
    0xaf, 0xf2, 0x0e, 0xc9, 0x03, 0xd6, 0x90, 0x01, 0x81, 0xf1, 0xda, 0xc3,
    0x6e, 0x88, 0xbe, 0x12, 0x21, 0x0c, 0x6f, 0x62, 0x75, 0x43, 0xa8, 0xc6,
    0xd1, 0x40, 0x62, 0x96, 0xf8, 0x1e, 0xa3, 0x5d, 0x9f, 0xf7, 0xdb, 0x8e,
    0xba, 0x78, 0x4d, 0xef, 0x58, 0x5c, 0x93, 0x2d, 0x15, 0x25, 0x39, 0x1d,
    0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x49, 0x30, 0x47, 0x30, 0x45, 0x06,
    0x03, 0x55, 0x1d, 0x01, 0x04, 0x3e, 0x30, 0x3c, 0x80, 0x10, 0xec, 0xd2,
    0x82, 0xce, 0x3b, 0x12, 0xd2, 0xef, 0x3f, 0xc8, 0x8d, 0x9c, 0xb9, 0x07,
    0x7d, 0x56, 0xa1, 0x16, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x13, 0x09, 0x54, 0x65, 0x73, 0x74, 0x52, 0x6f, 0x6f,
    0x74, 0x31, 0x82, 0x10, 0x68, 0x99, 0x65, 0xc8, 0xe3, 0xb6, 0xbd, 0x81,
    0x45, 0x85, 0x00, 0x61, 0x17, 0x34, 0x2e, 0xde, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x03,
    0x81, 0x81, 0x00, 0x48, 0x97, 0xd6, 0xad, 0x9d, 0xa3, 0x9c, 0x45, 0xfc,
    0xd6, 0x82, 0x51, 0x06, 0x94, 0xfc, 0x3f, 0xed, 0x8d, 0xab, 0xcd, 0x87,
    0x9c, 0x80, 0x22, 0x30, 0x14, 0x27, 0xc7, 0x89, 0x04, 0x08, 0x2c, 0x51,
    0x68, 0x6a, 0xf5, 0x19, 0x6a, 0x57, 0x77, 0x4e, 0xc6, 0x55, 0xbf, 0xaa,
    0x05, 0x42, 0xaa, 0xbf, 0xf8, 0x4d, 0xc5, 0x03, 0x97, 0x65, 0x67, 0xca,
    0x52, 0xd3, 0xa7, 0x61, 0xb1, 0x01, 0xac, 0xdd, 0x4e, 0xc1, 0x96, 0x70,
    0xe4, 0xf5, 0xe0, 0x99, 0x28, 0xf5, 0xa0, 0xcf, 0xb2, 0x9e, 0x23, 0x00,
    0xf0, 0xd2, 0x18, 0x73, 0x30, 0xbb, 0xe4, 0x33, 0xdb, 0x3e, 0xd3, 0x4e,
    0x4e, 0x56, 0x12, 0x36, 0x21, 0x28, 0x5d, 0x3b, 0x43, 0xe1, 0xf3, 0x9a,
    0xd1, 0x2d, 0xad, 0x31, 0xfb, 0x40, 0x9b, 0x57, 0xb2, 0xb5, 0x9f, 0x6e,
    0x8e, 0x39, 0xff, 0x57, 0x20, 0xd2, 0x44, 0xb8, 0xa3, 0x49, 0xfb, 0x31,
    0x81, 0xd1, 0x30, 0x81, 0xce, 0x02, 0x01, 0x01, 0x30, 0x28, 0x30, 0x14,
    0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x54,
    0x65, 0x73, 0x74, 0x52, 0x6f, 0x6f, 0x74, 0x31, 0x02, 0x10, 0x68, 0x99,
    0x65, 0xc8, 0xe3, 0xb6, 0xbd, 0x81, 0x45, 0x85, 0x00, 0x61, 0x17, 0x34,
    0x2e, 0xde, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x81, 0x80, 0x92,
    0xe1, 0x78, 0xb6, 0x81, 0x2d, 0xfd, 0x8f, 0xb1, 0x44, 0xfb, 0xdc, 0xc1,
    0xf5, 0x0e, 0x11, 0xde, 0xfd, 0x38, 0xcd, 0x83, 0x59, 0xf2, 0xb9, 0x50,
    0xe4, 0xb6, 0x98, 0x0f, 0x75, 0xbc, 0x60, 0xe2, 0x1c, 0xa0, 0x0f, 0x01,
    0xb0, 0xcc, 0xe6, 0x75, 0x3b, 0xba, 0xe2, 0x4f, 0x8e, 0x58, 0xe0, 0x93,
    0x3a, 0xa7, 0xf2, 0xe1, 0x77, 0x5c, 0xf6, 0xc0, 0xd0, 0x31, 0x68, 0x77,
    0x2b, 0x36, 0xa7, 0x91, 0x31, 0xf6, 0x1a, 0x7a, 0x3c, 0x85, 0x07, 0xcc,
    0x8d, 0x12, 0x2a, 0x0c, 0xa6, 0xd9, 0x68, 0x83, 0x32, 0x8b, 0x66, 0x7d,
    0x7d, 0xda, 0x11, 0x2a, 0x20, 0x14, 0xd6, 0x75, 0x89, 0xc2, 0x02, 0x31,
    0xf5, 0x5a, 0x51, 0x59, 0x94, 0xbe, 0x46, 0x52, 0xe1, 0x6c, 0x43, 0x5f,
    0x5c, 0x5d, 0x3b, 0xe4, 0xce, 0xa5, 0x8f, 0x51, 0xcf, 0xb1, 0x94, 0x82,
    0xe8, 0x6a, 0x86, 0x3b, 0xba, 0xd1, 0xec, 0x30, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38, 0x39
};

static EFI_GUID mVarVendorGuid =
    { 0x15EDF297, 0xE832, 0x4d30, { 0x82, 0x00, 0xA5, 0x25, 0xA9, 0x31, 0xE3, 0x3E } };

static void test_auth_variable_DER_conf(void)
{
    EFI_STATUS status;
    uint32_t attr;
    uint64_t index;
    uint64_t max_variable_storage_size;
    uint64_t remaining_variable_storage_size;
    uint64_t maximum_variable_size;
    uint32_t attr_array[] = {
        //
        //  For 1 attribute.
        //
        EFI_VARIABLE_NON_VOLATILE,
        EFI_VARIABLE_BOOTSERVICE_ACCESS,
        EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,

        //
        //  For 2 attributes.
        //
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
        EFI_VARIABLE_NON_VOLATILE |
                EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,

        EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,

        EFI_VARIABLE_BOOTSERVICE_ACCESS |
                EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,

        //
        //  For 3 attributes.
        //
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
                EFI_VARIABLE_BOOTSERVICE_ACCESS,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,

        //
        //  For 4 attributes.
        //
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
                EFI_VARIABLE_BOOTSERVICE_ACCESS |
                EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
    };

    attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
           EFI_VARIABLE_BOOTSERVICE_ACCESS |
           EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

    status = testutil_set_variable(L"AuthVarDER", &mVarVendorGuid, attr,
                         sizeof(invalid_der), (void *)invalid_der);

    munit_assert(status == EFI_SECURITY_VIOLATION);

    for (index = 0; index < sizeof(attr_array) / sizeof(attr_array[0]);
         index = index + 1) {
        attr = attr_array[index];
        attr |= EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS;

        status = testutil_set_variable(L"AuthVarDER", &mVarVendorGuid, attr,
                             sizeof(valid_der), (void *)valid_der);

        printf("%s:fail: index=%lu\n", __func__, index);
        printf("status=%s\n", efi_status_str(status));
        munit_assert(status == EFI_UNSUPPORTED);

        status = testutil_set_variable(L"AuthVarDER", &mVarVendorGuid, attr,
                             sizeof(invalid_der), (void *)invalid_der);

        munit_assert(status == EFI_UNSUPPORTED);

        status = testutil_query_variable_info(attr, &max_variable_storage_size,
                                   &remaining_variable_storage_size,
                                   &maximum_variable_size);

        munit_assert(status == EFI_SUCCESS || status == EFI_UNSUPPORTED);
    }
}

void test_auth(void)
{
    auth_lib_load("data/certs/PK.auth");
    auth_lib_initialize();
    test_auth_variable_DER_conf();
    storage_deinit();
}
