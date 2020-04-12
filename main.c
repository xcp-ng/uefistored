#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* WARNING: Could not reconcile some variable overlaps */

int main(int argc,char **argv)

{
#if 0
  bool bVar2;
  uint uVar5;
  char getopt_ret;
  int __fd;
  int ret;
  uint uVar3;
  byte bVar1;
  char cVar6;
  size_t __n_00;
  char *pcVar8;
  ulong _domain;
  long val;
  uint *puVar9;
  char *__nptr;
  void *port_array;
  uint _vcpu_count;
  undefined4 uVar4;
  int iVar7;
  int *piVar6;
  long local_RCX_963;
  uint uVar7;
  ulong vcpu_iter;
  size_t __n;
  int counter;
  char *__format;
  char *__nptr_00;
  char *__format_01;
  char *__format_00;
  sigaction *psVar8;
  uint uVar9;
  uint uVar10;
  uint *puVar11;
  bool bVar12;
  byte bVar10;
  uint longindex;
  uint portio_number;
  char *local_228;
  long param_result;
  uint *ioreq_server_address;
  char *local_210;
  char *stringbuf [8];
  ulong xc_dominfo;
  ulong local_1c0;
  int local_1b4;
  byte local_1aa;
  int local_17c;
  undefined local_158 [128];
  undefined *_signal_handler;
  sigaction *__act;
  
  bVar10 = 0;
  argc = argc & 0xffffffff;
  DAT_0060d888 = basename(*argv);
  __nptr_00 = (char *)0x0;
LAB_00404ac0:
  getopt_ret = getopt_long(argc,argv,0x40abc8,&options_array,&longindex);
  if (getopt_ret == -1) {
    if (((__nptr_00 == (char *)0x0) || ((code **)DAT_0060d8c8 == (code **)0x0)) ||
       (cVar6 = (*((code **)DAT_0060d8c8)[1])(), cVar6 == '\0')) goto LAB_00405479;
    _domain = strtol(__nptr_00,&local_228,0);
    if (*local_228 == '\0') {
      sigfillset((sigset_t *)local_158);
      local_RCX_963 = 0x26;
      psVar8 = (sigaction *)&_signal_handler;
      while (local_RCX_963 != 0) {
        local_RCX_963 = local_RCX_963 + -1;
        psVar8 = (sigaction *)((long)psVar8 + (ulong)bVar10 * -8 + 4);
        *(undefined4 *)&psVar8->__sigaction_handler = 0;
        psVar8 = psVar8;
      }
      _signal_handler = signal_handler;
      sigaction(0xf,(sigaction *)&_signal_handler,(sigaction *)0x0);
      sigdelset((sigset_t *)local_158,0xf);
      sigaction(2,(sigaction *)&_signal_handler,(sigaction *)0x0);
      sigdelset((sigset_t *)local_158,2);
      sigaction(1,(sigaction *)&_signal_handler,(sigaction *)0x0);
      sigdelset((sigset_t *)local_158,1);
      sigaction(6,(sigaction *)&_signal_handler,(sigaction *)0x0);
      sigdelset((sigset_t *)local_158,6);
      sigprocmask(0,(sigset_t *)local_158,(sigset_t *)0x0);
      param_result = 0;
      ioreq_server_address = (uint *)0x0;
      DAT_0060d86c = 0xffffffff;
      domain = (ushort)_domain;
      val = xc_interface_open(0,0,0);
      if (val == 0) {
        fprintf(stderr,"%s: ","varstored_initialize");
        puVar9 = (uint *)__errno_location();
        __nptr_00 = strerror(*puVar9);
        vcpu_iter = (ulong)*puVar9;
        __format_01 = "Failed to open xc_interface handle: %d, %s\n";
      }
      else {
        _domain = _domain & 0xffff;
        __fd = xc_domain_getinfo(val,_domain,1,&xc_dominfo);
        if (-1 < __fd) {
          if ((int)_domain != (int)xc_dominfo) {
            argc = 0;
            fprintf(stderr,"%s: ","varstored_initialize");
            fprintf(stderr,"Domid %u does not match expected %u\n",xc_dominfo & 0xffffffff,_domain);
            fflush(stderr);
            goto LAB_00404fab;
          }
          bVar2 = true;
          counter = 0;
          vcpu_count = local_17c + 1;
          printf("%s: ","varstored_initialize");
          printf("%d vCPU(s)\n",(ulong)vcpu_count);
          fflush(stdout);
          while( true ) {
            ret = xc_hvm_param_get(val,(ulong)domain,0x21,&param_result);
            if (ret < 0) {
              fprintf(stderr,"%s: ","varstored_initialize");
              puVar9 = (uint *)__errno_location();
              __nptr_00 = strerror(*puVar9);
              vcpu_iter = (ulong)*puVar9;
              __format_01 = "xc_hvm_param_get failed: %d, %s";
              goto LAB_004053da;
            }
            if ((bVar2) || (param_result != 0)) break;
LAB_004050df:
            if (counter == 0) {
              printf("%s: ");
              counter = 1;
              printf("Waiting for ioreq server");
              fflush(stdout);
              usleep(100000);
            }
            else {
              counter = counter + 1;
              usleep(100000);
              if (10 < counter) {
                counter = 0;
              }
            }
            if (param_result != 0) goto LAB_0040513e;
            bVar2 = false;
          }
          printf("%s: ","varstored_initialize");
          printf("HVM_PARAM_NR_IOREQ_SERVER_PAGES = %ld\n");
          fflush(stdout);
          if (param_result == 0) goto LAB_004050df;
LAB_0040513e:
          xc_interface_close(val);
          xendevicemodel_handle = xendevicemodel_open(0,0);
          if (xendevicemodel_handle == 0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to open xendevicemodel handle: %d, %s\n";
LAB_00405348:
            val = 0;
            argc = 0;
            fprintf(stderr,__format,vcpu_iter,__nptr);
            fflush(stderr);
            goto LAB_00404fab;
          }
          xenforeignmemory_handle = xenforeignmemory_open(0,0);
          if (xenforeignmemory_handle == 0) {
LAB_0040547e:
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to open xenforeignmemory handle: %d, %s\n";
            goto LAB_00405348;
          }
          xenevtchn_handle = xenevtchn_open(0,0);
          if (xenevtchn_handle == 0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to open evtchn handle: %d, %s\n";
            goto LAB_00405348;
          }
          counter = xentoolcore_restrict_all(_domain);
          if (counter < 0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to restrict Xen handles: %d, %s\n";
            goto LAB_00405348;
          }
          counter = xendevicemodel_create_ioreq_server
                              (xendevicemodel_handle,(ulong)domain,1,&ioreq_server_id);
          if (counter < 0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to create ioreq server: %d, %s\n";
            goto LAB_00405348;
          }
          DAT_0060d842 = 1;
          DAT_0060d848 = xenforeignmemory_map_resource
                                   (xenforeignmemory_handle,(ulong)domain,0,(ulong)ioreq_server_id,0
                                    ,2,&ioreq_server_address,3,0);
          if (DAT_0060d848 == 0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to map ioreq server resource: %d, %s\n";
            goto LAB_00405348;
          }
          _ioreq_server_address = ioreq_server_address;
          iopage = ioreq_server_address + 0x400;
          printf("%s: ","varstored_initialize");
          printf("iopage = %p\n",iopage);
          fflush(stdout);
          printf("%s: ","varstored_initialize");
          printf("buffered_iopage = %p\n",_ioreq_server_address);
          fflush(stdout);
          counter = xendevicemodel_get_ioreq_server_info
                              (xendevicemodel_handle,(ulong)domain,(ulong)ioreq_server_id,0,0);
          if (counter < 0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to get ioreq server info: %d, %s\n";
            goto LAB_00405348;
          }
          printf("%s: ","varstored_initialize");
          printf("ioservid = %u\n",(ulong)ioreq_server_id);
          fflush(stdout);
          counter = xendevicemodel_set_ioreq_server_state
                              (xendevicemodel_handle,(ulong)domain,(ulong)ioreq_server_id);
          _vcpu_count = vcpu_count;
          if (counter != 0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to set ioreq server state: %d, %s\n";
            goto LAB_00405348;
          }
          port_array = malloc((ulong)vcpu_count << 2);
          _port_array = port_array;
          if (port_array == (void *)0x0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to alloc port array: %d, %s\n";
            goto LAB_00405348;
          }
          val = 0;
          while ((uint)val < _vcpu_count) {
            *(undefined4 *)((long)port_array + val * 4) = 0xffffffff;
            val = val + 1;
          }
          val = 0;
          while ((uint)val < vcpu_count) {
            counter = xenevtchn_bind_interdomain
                                (xenevtchn_handle,(ulong)domain,
                                 (ulong)iopage[(long)(int)(uint)val * 8 + 6]);
            if (counter < 0) {
              fprintf(stderr,"%s: ","varstored_initialize");
              puVar9 = (uint *)__errno_location();
              __nptr = strerror(*puVar9);
              vcpu_iter = (ulong)*puVar9;
              __format = "Failed to failed to bind port: %d, %s\n";
              goto LAB_00405348;
            }
            *(int *)((long)_port_array + val * 4) = counter;
            val = val + 1;
          }
          _vcpu_count = 0;
          while (_vcpu_count < vcpu_count) {
            printf("%s: ","varstored_initialize");
            vcpu_iter = (ulong)_vcpu_count;
            val = (long)(int)_vcpu_count;
            _vcpu_count = _vcpu_count + 1;
            printf("VCPU%d: %u -> %u\n",vcpu_iter,(ulong)iopage[val * 8 + 6]);
            fflush(stdout);
          }
          uVar3 = xenevtchn_bind_interdomain(xenevtchn_handle,(ulong)domain,(ulong)portio_number);
          if ((int)uVar3 < 0) {
            fprintf(stderr,"%s: ","varstored_initialize");
            puVar9 = (uint *)__errno_location();
            __nptr = strerror(*puVar9);
            vcpu_iter = (ulong)*puVar9;
            __format = "Failed to failed to bind buffered port: %d, %s\n";
            goto LAB_00405348;
          }
          DAT_0060d86c = uVar3;
          printf("%s: ","varstored_initialize");
          printf("%u -> %u\n",(ulong)DAT_0060d868,(ulong)DAT_0060d86c);
          fflush(stdout);
          counter = init_io_port(xendevicemodel_handle,xenforeignmemory_handle,(ulong)domain);
          if ((-1 < counter) && (cVar6 = load_auth_files(), cVar6 != '\0')) {
            argc = xs_open(0);
            if (argc == 0) {
              fprintf(stderr,"%s: ","varstored_initialize");
              puVar9 = (uint *)__errno_location();
              __nptr_00 = strerror(*puVar9);
              _vcpu_count = *puVar9;
              __format_01 = "Couldn\'t open xenstore: %d, %s";
            }
            else {
              snprintf((char *)stringbuf,0x40,"/local/domain/%u/platform/secureboot");
              __nptr_00 = (char *)xs_read(argc,0,stringbuf);
              if (__nptr_00 == (char *)0x0) {
                success = false;
              }
              else {
                counter = strcmp(__nptr_00,"true");
                success = counter == 0;
              }
              free(__nptr_00);
              printf("%s: ","initialize_settings");
              __nptr_00 = "true";
              if (success == false) {
                __nptr_00 = "false";
              }
              printf("Secure boot enable: %s\n",__nptr_00);
              fflush(stdout);
              snprintf((char *)stringbuf,0x40,"/local/domain/%u/platform/auth-enforce");
              __nptr_00 = (char *)xs_read(argc,0,stringbuf);
              if (__nptr_00 == (char *)0x0) {
                DAT_0060d4e1 = true;
              }
              else {
                counter = strcmp(__nptr_00,"false");
                DAT_0060d4e1 = counter != 0;
              }
              free(__nptr_00);
              printf("%s: ","initialize_settings");
              __nptr_00 = "enforcing";
              if (DAT_0060d4e1 == false) {
                __nptr_00 = "permissive";
              }
              printf("Authenticated variables: %s\n",__nptr_00);
              fflush(stdout);
              local_210 = (char *)0x0;
              stringbuf[0] = (char *)0x0;
              _vcpu_count = getpid();
              counter = asprintf(&local_210,"%u",(ulong)_vcpu_count);
              if ((counter == -1) ||
                 (counter = asprintf(stringbuf,"/local/domain/%u/varstored-pid",(ulong)domain),
                 counter == -1)) {
                free(stringbuf[0]);
                free(local_210);
              }
              else {
                val = -1;
                __nptr_00 = local_210;
                do {
                  _vcpu_count = (uint)val;
                  if (val == 0) break;
                  val = val + -1;
                  _vcpu_count = (uint)val;
                  cVar6 = *__nptr_00;
                  __nptr_00 = __nptr_00 + (ulong)bVar10 * -2 + 1;
                } while (cVar6 != '\0');
                cVar6 = xs_write(argc,0,stringbuf[0],local_210,(ulong)(~_vcpu_count - 1));
                free(stringbuf[0]);
                free(local_210);
                if (cVar6 != '\0') {
LAB_00405a93:
                  xs_close(argc);
                  cVar6 = containerize(DAT_0060d870,(ulong)DAT_0060d880,(ulong)DAT_0060d878);
                  if (cVar6 == '\0') goto LAB_004056e6;
                  if (DAT_0060d8c0 == '\0') {
                    counter = (*((code **)DAT_0060d8c8)[2])();
                    if (counter == 0) {
                      fprintf(stderr,"%s: ","varstored_initialize");
                      __n = 0x1e;
                      __nptr_00 = "Failed to initialize backend!\n";
                    }
                    else {
                      cVar6 = init_uefi_variables();
                      if (cVar6 == '\0') {
                        fprintf(stderr,"%s: ","varstored_initialize");
                        __n = 0x1a;
                        __nptr_00 = "Failed to setup variables\n";
                      }
                      else {
                        if ((counter != 2) || (cVar6 = setup_keys(), cVar6 != '\0'))
                        goto LAB_00405ae1;
                        fprintf(stderr,"%s: ","varstored_initialize");
                        __n = 0x15;
                        __nptr_00 = "Failed to setup keys\n";
                      }
                    }
                  }
                  else {
                    cVar6 = (*((code **)DAT_0060d8c8)[4])();
                    if (cVar6 != '\0') {
LAB_00405ae1:
                      cleanup();
                      uVar4 = xenevtchn_fd(xenevtchn_handle);
                      stringbuf[0] = (char *)(ulong)CONCAT24(0x19,uVar4);
                      counter = DAT_0060d640;
                      do {
                        while( true ) {
                          if ((counter == 0) ||
                             (iVar7 = poll((pollfd *)stringbuf,1,-1), counter = DAT_0060d640,
                             DAT_0060d640 == 0)) goto LAB_00405c0e;
                          if (iVar7 < 1) break;
                          if (((ulong)stringbuf[0] & 0x1000000000000) != 0) {
                            _vcpu_count = xenevtchn_pending(xenevtchn_handle);
                            counter = DAT_0060d640;
                            if (-1 < (int)_vcpu_count) {
                              if (_vcpu_count == DAT_0060d86c) {
                                xenevtchn_unmask(xenevtchn_handle);
                                while( true ) {
                                  _vcpu_count = _ioreq_server_address[1];
                                  counter = DAT_0060d640;
                                  uVar5 = *_ioreq_server_address;
                                  if (*_ioreq_server_address == _vcpu_count) break;
                                  do {
                                    uVar9 = uVar5 + 1;
                                    xc_dominfo = (ulong)((_ioreq_server_address +
                                                         (ulong)(uVar5 % 0x1ff) * 2)[2] >> 0xc);
                                    if ((int)(1 << (*(byte *)((long)(_ioreq_server_address +
                                                                    (ulong)(uVar5 % 0x1ff) * 2) + 9)
                                                    >> 2 & 3)) == 8) {
                                      uVar9 = uVar5 + 2;
                                    }
                                    handle_ioreq(&xc_dominfo);
                                    uVar5 = uVar9;
                                  } while (_vcpu_count != uVar9);
                                  *_ioreq_server_address = _vcpu_count;
                                }
                              }
                              else {
                                val = 0;
                                vcpu_iter = 0;
                                if (vcpu_count != 0) {
                                  while( true ) {
                                    if (_vcpu_count == *(uint *)((long)_port_array + val * 4)) {
                                      xenevtchn_unmask(xenevtchn_handle,(ulong)_vcpu_count);
                                      puVar11 = iopage + vcpu_iter * 8;
                                      if ((*(byte *)((long)puVar11 + 0x1e) & 0xf) == 1) {
                                        *(byte *)((long)puVar11 + 0x1e) =
                                             *(byte *)((long)puVar11 + 0x1e) & 0xf0 | 2;
                                        handle_ioreq(puVar11);
                                        *(byte *)((long)puVar11 + 0x1e) =
                                             *(byte *)((long)puVar11 + 0x1e) & 0xf0 | 3;
                                        xenevtchn_notify(xenevtchn_handle);
                                      }
                                      else {
                                        fwrite("IO request not ready\n",1,0x15,stderr);
                                      }
                                    }
                                    uVar7 = (int)val + 1;
                                    val = val + 1;
                                    counter = DAT_0060d640;
                                    if (vcpu_count <= uVar7) break;
                                    vcpu_iter = (ulong)uVar7;
                                  }
                                }
                              }
                            }
                          }
                        }
                      } while ((iVar7 == 0) || (piVar6 = __errno_location(), *piVar6 == 4));
LAB_00405c0e:
                      bVar1 = (*((code **)DAT_0060d8c8)[3])();
                      return (ulong)(bVar1 ^ 1);
                    }
                    fprintf(stderr,"%s: ","varstored_initialize");
                    __n = 0x12;
                    __nptr_00 = "Failed to resume!\n";
                  }
                  fwrite(__nptr_00,1,__n,stderr);
                  val = 0;
                  argc = 0;
                  fflush(stderr);
                  goto LAB_00404fab;
                }
              }
              fprintf(stderr,"%s: ","varstored_initialize");
              puVar9 = (uint *)__errno_location();
              __nptr_00 = strerror(*puVar9);
              _vcpu_count = *puVar9;
              __format_01 = "Failed to write pid to xenstore: %d, %s\n";
            }
            val = 0;
            fprintf(stderr,__format_01,(ulong)_vcpu_count,__nptr_00);
            fflush(stderr);
            goto LAB_00404fab;
          }
LAB_004056e6:
          val = 0;
          argc = 0;
          goto LAB_00404fab;
        }
        fprintf(stderr,"%s: ","varstored_initialize");
        puVar9 = (uint *)__errno_location();
        __nptr_00 = strerror(*puVar9);
        vcpu_iter = (ulong)*puVar9;
        __format_01 = "Failed to get domain info: %d, %s\n";
      }
LAB_004053da:
      argc = 0;
      fprintf(stderr,__format_01,vcpu_iter,__nptr_00);
      fflush(stderr);
LAB_00404fab:
      xc_interface_close(val);
      xs_close(argc);
      cleanup();
      teardown_xen_resources();
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    __format_00 = "invalid domain \'%s\'\n";
    __format_01 = __nptr_00;
  }
  else {
    if (getopt_ret != '\0') {
LAB_00405479:
      print_usage();
      goto LAB_0040547e;
    }
    printf("%s: ",&DAT_0040b317);
    printf("--%s = \'%s\'\n",(&options_array)[(long)(int)longindex * 4],optarg);
    fflush(stdout);
    __format_01 = optarg;
    bVar12 = longindex == 9;
    switch(longindex) {
    case 0:
      __nptr_00 = optarg;
      goto LAB_00404ac0;
    case 1:
      DAT_0060d8c0 = '\x01';
      goto LAB_00404ac0;
    case 2:
      DAT_0060d4e0 = 0;
      goto LAB_00404ac0;
    case 3:
      DAT_0060d880 = 1;
      goto LAB_00404ac0;
    case 4:
      val = strtol(optarg,&local_228,0);
      DAT_0060d87c = (undefined4)val;
      cVar6 = *local_228;
      __format_01 = optarg;
      break;
    case 5:
      val = strtol(optarg,&local_228,0);
      DAT_0060d878 = (uint)val;
      cVar6 = *local_228;
      __format_01 = optarg;
      break;
    case 6:
      DAT_0060d870 = __strdup();
      goto LAB_00404ac0;
    case 7:
      counter = open(optarg,0x80241,0x180);
      if (counter == -1) {
        fprintf(stderr,"%s: ","create_pidfile");
        puVar9 = (uint *)__errno_location();
        __nptr_00 = strerror(*puVar9);
        fprintf(stderr,"Could not open pidfile \'%s\': %d, %s\n",__format_01,(ulong)*puVar9,
                __nptr_00);
        fflush(stderr);
        goto LAB_00404c45;
      }
      iVar7 = lockf(counter,2,0);
      if (iVar7 == -1) {
        fprintf(stderr,"%s: ","create_pidfile");
        __n_00 = 0x17;
        __nptr_00 = "Failed to lock pidfile\n";
      }
      else {
        _vcpu_count = getpid();
        iVar7 = asprintf(&_signal_handler,"%u\n",(ulong)_vcpu_count);
        if (iVar7 != -1) {
          __n_00 = write(counter,_signal_handler,(long)iVar7);
          if (__n_00 != (long)iVar7) {
            fprintf(stderr,"%s: ","create_pidfile");
            fwrite("Failed to write to pidfile\n",1,0x1b,stderr);
            fflush(stderr);
            free(_signal_handler);
            close(counter);
            goto LAB_00404c45;
          }
          free(_signal_handler);
          goto LAB_00404ac0;
        }
        fprintf(stderr,"%s: ","create_pidfile");
        __n_00 = 0xe;
        __nptr_00 = "Out of memory\n";
      }
      fwrite(__nptr_00,1,__n_00,stderr);
      fflush(stderr);
      close(counter);
      goto LAB_00404c45;
    case 8:
      val = 7;
      pcVar8 = "xapidb";
      do {
        if (val == 0) break;
        val = val + -1;
        bVar12 = *__format_01 == *pcVar8;
        __format_01 = __format_01 + (ulong)bVar10 * -2 + 1;
        pcVar8 = pcVar8 + (ulong)bVar10 * -2 + 1;
      } while (bVar12);
      if (!bVar12) {
        fprintf(stderr,"Invalid backend \'%s\'\n");
        goto LAB_00405479;
      }
      DAT_0060d8c8 = &PTR_FUN_0040b480;
      goto LAB_00404ac0;
    case 9:
      if ((code **)DAT_0060d8c8 == (code **)0x0) {
LAB_00405a73:
        fwrite("Must set backend before backend args\n",1,0x25,stderr);
        print_usage();
        goto LAB_00405a93;
      }
      pcVar8 = strchr(optarg,0x3a);
      if (pcVar8 == (char *)0x0) {
        fprintf(stderr,"Invalid argument \'%s\'\n",__format_01);
        print_usage();
        goto LAB_00405a73;
      }
      *pcVar8 = '\0';
      cVar6 = (*(code *)*DAT_0060d8c8)(optarg,pcVar8 + 1);
      if (cVar6 == '\0') {
        fprintf(stderr,"Invalid argument \'%s:%s\'\n",optarg,pcVar8 + 1);
        print_usage();
switchD_00404b38_caseD_a:
                    /* WARNING: Subroutine does not return */
        __assert_fail("0","varstored.c",0x313,"main");
      }
      goto LAB_00404ac0;
    default:
      goto switchD_00404b38_caseD_a;
    }
    optarg = __format_01;
    if (cVar6 == '\0') goto LAB_00404ac0;
    __format_00 = "invalid uid \'%s\'\n";
  }
  fprintf(stderr,__format_00,__format_01);
LAB_00404c45:
                    /* WARNING: Subroutine does not return */
  exit(1);
#endif
    return 0;
}

