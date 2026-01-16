/*
 * Ghidra Type Definitions
 * Maps Ghidra's decompiler types to standard C types
 */

#ifndef GHIDRA_TYPES_H
#define GHIDRA_TYPES_H

#include <stdint.h>
#include <stdbool.h>

/* Ghidra undefined types */
typedef uint8_t  undefined;
typedef uint8_t  undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;

/* Common types */
typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;

/* Note: size_t is provided by <stddef.h> or <cstddef> - do not redefine */

#endif /* GHIDRA_TYPES_H */
