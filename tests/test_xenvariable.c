#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include "xenvariable.h"
#include "backends/filedb.h"
#include "mock/XenVariable.h"
#include "test_common.h"
#include "common.h"

static uint8_t comm_buf_phys[SHMEM_PAGES * PAGE_SIZE];
static void *comm_buf = comm_buf_phys;

static void pre_test(void)
{
    int ret;

    ret = filedb_init("./test.db", "./test_var_len.db", "./test_var_attrs.db");
    test(ret == 0);
}

static void post_test(void)
{
    filedb_deinit();
    filedb_destroy();
    memset(comm_buf, 0, SHMEM_PAGES * PAGE_SIZE);
}

#define DO_TEST(test)                                   \
    do  {                                               \
        pre_test();                                         \
        test();                                         \
        post_test();                                    \
    }  while ( 0 )

int _logfd = -1;

/* Test Data */
const char rtcnamebytes[] = {
    0, 'R',
    0, 'T',
    0, 'C',
    0,  0,
};

static inline uint64_t getstatus(void *p)
{
    return *((uint64_t*) p);
}

static void deinit(void)
{
}

static void test_nonexistent_variable_returns_not_found(void)
{
    EFI_STATUS status;
    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr;
    uint64_t data;
    uint64_t datasize = sizeof(data);
    void *vnp;
    size_t len;

    comm_buf = comm_buf_phys;
    mock_xenvariable_set_buffer(comm_buf);

    guid[0] = 0xde;

    /* Build a GetVariable() command */
    status = XenGetVariable(rtcname, &guid, &attr, &datasize, (void*)&data);

    /* Handle the command */
    xenvariable_handle_request(comm_buf);

   // xenvariable_handle_request(comm_buf);
    test(getstatus(comm_buf) == EFI_NOT_FOUND);
}

static inline void
unserialize_data(uint8_t **ptr, void *Data, uint64_t *DataSize)
{
  memcpy(DataSize, *ptr, sizeof(*DataSize));
  *ptr += sizeof(*DataSize);
  memcpy(Data, *ptr, *DataSize);
  *ptr += *DataSize;
}

static inline uint64_t
unserialize_uintn(uint8_t **ptr)
{
  uint64_t ret;

  memcpy(&ret, *ptr, sizeof ret);
  *ptr += sizeof ret;

  return ret;
}

static inline uint32_t
unserialize_uint32(uint8_t **ptr)
{
    uint32_t ret;

    printf("%s:%d\n", __func__, __LINE__);
    memcpy(&ret, *ptr, sizeof ret);
    printf("%s:%d\n", __func__, __LINE__);
    *ptr += sizeof ret;
    printf("%s:%d\n", __func__, __LINE__);

    return ret;
}

static inline uint64_t
unserialize_uint64(uint8_t **ptr)
{
  uint64_t ret;

  memcpy(&ret, *ptr, sizeof ret);
  *ptr += sizeof ret;

  return ret;
}

static inline void
unserialize_guid(uint8_t **ptr, uint8_t *Guid)
{
  memcpy (Guid, *ptr, 16);
  *ptr += 16;
}

static inline EFI_STATUS
unserialize_result(uint8_t **ptr)
{
  EFI_STATUS status;
  uint8_t *p = *ptr;

  if ( !p )
  {
      fprintf(stderr, "%s: %d: ERROR: null pointer\n", __func__, __LINE__);
      return -1;
  }

  memcpy(&status, *ptr, sizeof status);
  *((uint64_t*)ptr) += sizeof(status);

  return status;
}


static EFI_STATUS XenGetVariableEnd(
        void *name,
        uint32_t *Attributes,
        void *Data,
        size_t *DataSize)
{
    uint32_t attr;
    uint8_t *ptr = comm_buf;
    EFI_STATUS status;

    status = unserialize_result(&ptr);
    printf("%s:%d: status=%d\n", __func__, __LINE__, status);
    switch ( status )
    {
    case EFI_SUCCESS:
        if (!Data)
            return EFI_INVALID_PARAMETER;
        printf("%s:%d\n", __func__, __LINE__);
        attr = unserialize_uint32(&ptr);
        printf("%s:%d\n", __func__, __LINE__);
        if (Attributes)
            *Attributes = attr;
        printf("%s:%d\n", __func__, __LINE__);
        unserialize_data(&ptr, Data, DataSize);
        break;
    case EFI_BUFFER_TOO_SMALL:
        printf("%s:%d\n", __func__, __LINE__);
        *DataSize = unserialize_uintn(&ptr);
        break;
    default:
        break;
    }

    printf("%s:%d\n", __func__, __LINE__);
    return status;
}

static EFI_STATUS XenSetVariableEnd(void)
{
    return getstatus(comm_buf);
}

static void test_set_and_get(void)
{
    uint64_t status;

    char16_t *rtcname = (char16_t*)rtcnamebytes;
    uint8_t guid[16] = {0};
    uint32_t attr = 0;
    uint32_t indata = 0xdeadbeef;
    uint32_t outdata;
    size_t outsz = sizeof(outdata);
    void *vnp;
    size_t len;

    memset(guid, 0xab, 16);

    mock_xenvariable_set_buffer(comm_buf);

    /* Preset status byte to not success */
    *((uint64_t*)comm_buf) =  ~EFI_SUCCESS;
    assert(getstatus(comm_buf) != EFI_SUCCESS);

    /* Perform GetVariable() command */
    status = XenSetVariable(rtcname, &guid, &attr, sizeof(indata), (void*)&indata);
    xenvariable_handle_request(comm_buf);
    status = XenSetVariableEnd();

    test(status == EFI_SUCCESS);

    /* Perform GetVariable() command */
    XenGetVariable(rtcname, &guid, &attr, &outsz, (void*)&outdata);
    xenvariable_handle_request(comm_buf);
    status = XenGetVariableEnd(rtcname, &attr, &outdata, &outsz);

    /* Assert that in/out values are equal */
    test(status == EFI_SUCCESS);
    test(outdata == indata);

    printf("outdata=0x%lx, indata=0x%lx\n", outdata, indata);
}


static void test_good_commands(void)
{
}

static void test_bad_commands(void)
{
    /* TODO: test large values, fuzz, etc... */
    test(0);
}

void test_xenvariable(void)
{
    DO_TEST(test_nonexistent_variable_returns_not_found);
    DO_TEST(test_set_and_get);
}
