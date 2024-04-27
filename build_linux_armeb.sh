#!/bin/sh
set -e

RELARGS="-O3 -DNDEBUG"
DBGARGS="-g -D_DEBUG"
CURARGS="$RELARGS"

armeb-buildroot-linux-uclibcgnueabi-as crypto/poly1305/poly1305-armeb.s -o poly1305-armeb.o
armeb-buildroot-linux-uclibcgnueabi-as crypto/chacha20/chacha20-armeb.s -o chacha20-armeb.o
armeb-buildroot-linux-uclibcgnueabi-g++ -I . -DWITH_NETWORK_BSD=1 -pthread -lrt -o tunsafe tunsafe_amalgam.cpp chacha20-armeb.o poly1305-armeb.o
