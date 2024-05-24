// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "tunsafe_types.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/aesgcm/aes.h"
#include "tunsafe_cpu.h"

#include <functional>
#include <string.h>

#if defined(OS_FREEBSD) || defined(OS_LINUX)
#include <time.h>
#include <stdlib.h>
typedef uint64 LARGE_INTEGER;

size_t packet_size = 8192;
uint64 max_bytes = 100 * 1024 * 1024;
void QueryPerformanceCounter(LARGE_INTEGER *x) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    fprintf(stderr, "clock_gettime failed\n");
    exit(1);
  }
  *x = (uint64)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

void QueryPerformanceFrequency(LARGE_INTEGER *x) {
  *x = 1000000000;
}
#elif defined(OS_MACOSX)
#include <mach/mach.h>
#include <mach/mach_time.h>
typedef uint64 LARGE_INTEGER;

void QueryPerformanceCounter(LARGE_INTEGER *x) {
  *x = mach_absolute_time();
}

void QueryPerformanceFrequency(LARGE_INTEGER *x) {
  mach_timebase_info_data_t timebase = { 0, 0 };
  if (mach_timebase_info(&timebase) != 0)
    abort();
  printf("numer/denom: %d %d\n", timebase.numer, timebase.denom);
  *x = timebase.denom * 1000000000;  
}

#endif

int gcm_self_test();


void *fake_glb;
void Benchmark() {

  int64 a, b, f;
  uint64 bytes;
  QueryPerformanceFrequency((LARGE_INTEGER*)&f);
#if WITH_AESGCM
  gcm_self_test();
#endif  // WITH_AESGCM

  PrintCpuFeatures();

  uint8 dst[1500 + 16];
  uint8 key[32] = {0, 1, 2, 3, 4, 5, 6};
  uint8 mac[16];

  fake_glb = dst;

  memset(dst, 0, 1500);
  bytes = 0;
  size_t i;
  RINFO("Benchmarking chacha20_encrypt...\n");
  QueryPerformanceCounter((LARGE_INTEGER*)&b);
  for (i = 0; bytes < max_bytes; i++) {
    chacha20poly1305_encrypt(dst, dst, packet_size, NULL, 0, i, key);
    bytes += packet_size;
  }
  QueryPerformanceCounter((LARGE_INTEGER*)&a); \
  RINFO("%s: %f MB/s\n", "chacha20-encrypt", (double)bytes / (1024 * 1024) / (a - b) * f); \

  bytes = 0;
  QueryPerformanceCounter((LARGE_INTEGER*)&b);
  for (i = 0; bytes < max_bytes; i++) {
    chacha20poly1305_decrypt_get_mac(dst, dst, packet_size, NULL, 0, i, key, mac);
    bytes += packet_size;
  }
  QueryPerformanceCounter((LARGE_INTEGER*)&a); \
  RINFO("%s: %f MB/s\n", "chacha20-decrypt", (double)bytes / (1024 * 1024) / (a - b) * f); \

  bytes = 0;
  QueryPerformanceCounter((LARGE_INTEGER*)&b);
  for (i = 0; bytes < max_bytes; i++) {
    poly1305_get_mac(dst, packet_size, NULL, 0, i, key, mac);
    bytes += packet_size;
  }
  QueryPerformanceCounter((LARGE_INTEGER*)&a); \
  RINFO("%s: %f MB/s\n", "poly1305-only", (double)bytes / (1024 * 1024) / (a - b) * f); \

#if WITH_AESGCM
  if (X86_PCAP_AES) {
    AesGcm128StaticContext sctx;
    CRYPTO_gcm128_init(&sctx, key, 128);

    RunOneBenchmark("aes128-gcm-encrypt", [&](size_t i) -> uint64 { aesgcm_encrypt(dst, dst, packet_size, NULL, 0, i, &sctx); return packet_size; });
    RunOneBenchmark("aes128-gcm-decrypt", [&](size_t i) -> uint64 { aesgcm_decrypt_get_mac(dst, dst, packet_size, NULL, 0, i, &sctx, mac); return packet_size; });
  }
#endif   //  WITH_AESGCM
}
