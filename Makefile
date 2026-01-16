# Makefile for keymanager reconstruction
# Builds reconstructed keymanager library and test programs
# Cross-compiling for ARM (HP TouchPad)

# ARM Toolchain (CodeSourcery 2009q1)
TOOLCHAIN = /home/herrie/Documents/GitHub/build/toolchain/cs09q1armel/build/arm-2009q1
CROSS_COMPILE = $(TOOLCHAIN)/bin/arm-none-linux-gnueabi-

# OpenSSL 1.1.1w location (ARM build)
OPENSSL_DIR = /home/herrie/webos/touchpad-kernel/doctor305/OpenSSL-11-Update/openssl-1.1.1w

# Build dependencies (Luna service, glib, cjson)
DEPS_DIR = /home/herrie/webos/touchpad-kernel/doctor305/build-deps
ISIS_STAGING = /home/herrie/webos/touchpad-kernel/doctor305/isis-project/staging/armv7
ROOTFS_LIB = /home/herrie/webos/touchpad-kernel/doctor305/untouched-rootfs/usr/lib

CXX = $(CROSS_COMPILE)g++
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
CXXFLAGS = -Wall -Wextra -g -O2 -I$(OPENSSL_DIR)/include -I$(ISIS_STAGING)/usr/include
LDFLAGS_CORE = -L$(OPENSSL_DIR) -lssl -lcrypto
LDFLAGS_FULL = -L$(OPENSSL_DIR) -lssl -lcrypto -L$(ISIS_STAGING)/usr/lib -lsqlite3

# Rootfs lib paths for linking
ROOTFS_BASE = /home/herrie/webos/touchpad-kernel/doctor305/untouched-rootfs
# Toolchain sysroot (has crt1.o, libc, etc.)
SYSROOT = $(TOOLCHAIN)/arm-none-linux-gnueabi/libc

# Luna Service flags
LUNA_CFLAGS = -I$(ISIS_STAGING)/usr/include \
              -I$(ISIS_STAGING)/usr/include/glib-2.0 \
              -I$(DEPS_DIR)/woce-build-support/staging/arm-none-linux-gnueabi/lib/glib-2.0/include
# Order matters: sysroot lib must come BEFORE rootfs lib to avoid picking up rootfs libc.so script
LUNA_LDFLAGS = --sysroot=$(SYSROOT) \
               -L$(SYSROOT)/lib -L$(SYSROOT)/usr/lib \
               -L$(ISIS_STAGING)/usr/lib -lglib-2.0 -lgthread-2.0 \
               -L$(ROOTFS_LIB) -llunaservice -lcjson -lmjson \
               -Wl,-rpath-link,$(ROOTFS_BASE)/lib \
               -Wl,-rpath-link,$(ROOTFS_LIB) \
               -Wl,-rpath,/usr/lib

# Core source files (no SQLite dependency)
CORE_SRCS = cpassword.cpp ckey.cpp ccrypto.cpp
CORE_OBJS = $(CORE_SRCS:.cpp=.o)

# Full source files (with SQLite)
FULL_SRCS = $(CORE_SRCS) ckeystore.cpp keymanager_misc.cpp ckeymanager.cpp
FULL_OBJS = $(FULL_SRCS:.cpp=.o)

# Test programs
TEST_KDF_SRCS = test_kdf.cpp
TEST_CRYPTO_SRCS = test_crypto.cpp
TEST_FULL_SRCS = test_keymanager.cpp

# Default: build core tests only (no SQLite required)
all: test_kdf test_crypto

# Full build (requires SQLite dev headers)
full: test_kdf test_crypto test_keymanager

# Simple KDF test
test_kdf: $(TEST_KDF_SRCS:.cpp=.o) cpassword.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_CORE)

# Crypto test (KDF + encryption)
test_crypto: $(TEST_CRYPTO_SRCS:.cpp=.o) $(CORE_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_CORE)

# Full test suite (requires SQLite)
test_keymanager: $(TEST_FULL_SRCS:.cpp=.o) $(FULL_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS_FULL)

# Object files
%.o: %.cpp keymanager_types.h keymanager_constants.h ghidra_types.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Run core tests (no SQLite required)
test: all
	@echo "=== Running KDF test ==="
	./test_kdf
	@echo ""
	@echo "=== Running Crypto test ==="
	./test_crypto

# Run full tests (requires SQLite)
test-full: full
	@echo "=== Running KDF test ==="
	./test_kdf
	@echo ""
	@echo "=== Running Crypto test ==="
	./test_crypto
	@echo ""
	@echo "=== Running full test suite ==="
	./test_keymanager

clean:
	rm -f $(FULL_OBJS) $(TEST_KDF_SRCS:.cpp=.o) $(TEST_CRYPTO_SRCS:.cpp=.o) $(TEST_FULL_SRCS:.cpp=.o) $(SERVICE_OBJS)
	rm -f test_kdf test_crypto test_keymanager keymanager
	rm -f /tmp/test_keymanager.db /tmp/test_*.txt /tmp/test_*.bin
	rm -f libkeymanager-core.a libkeymanager.a

# Static library (core only)
libkeymanager-core.a: $(CORE_OBJS)
	ar rcs $@ $^

# Static library (full, requires SQLite)
libkeymanager.a: $(FULL_OBJS)
	ar rcs $@ $^

# Service source files
SERVICE_SRCS = keyservice_handler.cpp
SERVICE_OBJS = $(SERVICE_SRCS:.cpp=.o)

# Luna service executable (complete keymanager service)
keymanager: $(SERVICE_OBJS) $(FULL_OBJS)
	$(CXX) $(CXXFLAGS) $(LUNA_CFLAGS) -o $@ $^ $(LDFLAGS_FULL) $(LUNA_LDFLAGS)

# Service object files need Luna headers
keyservice_handler.o: keyservice_handler.cpp keyservice_handler.h keymanager_types.h
	$(CXX) $(CXXFLAGS) $(LUNA_CFLAGS) -c $< -o $@

# Service build target (complete keymanager with Luna service)
service: keymanager

.PHONY: all full clean test test-full service
