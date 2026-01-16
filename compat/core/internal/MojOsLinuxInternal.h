// Copyright (c) 2009-2018 LG Electronics, Inc.
// Modified for ARM GCC 4.3.3 compatibility
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

#ifndef MOJOSLINUXINTERNAL_H_
#define MOJOSLINUXINTERNAL_H_

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 3)
/* Use for GCC 4.4 and greater - has built-in atomics */
inline MojInt32 MojAtomicCAS(MojAtomicT* a, MojInt32 oldVal, MojInt32 newVal)
{
	return __sync_val_compare_and_swap(&a->val, oldVal, newVal);
}
#elif defined(MOJ_X86)
/* x86 CAS using cmpxchg */
inline MojInt32 MojAtomicCAS(MojAtomicT* a, MojInt32 oldVal, MojInt32 newVal)
{
	MojInt32 prev;
	asm volatile(
		"lock cmpxchgl %1, %2"
		: "=a" (prev)
		: "r" (newVal), "m" (a->val), "0" (oldVal)
		: "memory");
	return prev;
}
#elif defined(MOJ_ARM)
/* ARM CAS using ldrex/strex (ARMv6+) */
inline MojInt32 MojAtomicCAS(MojAtomicT* a, MojInt32 oldVal, MojInt32 newVal)
{
	MojInt32 prev, tmp;
	asm volatile(
		"1:	ldrex %0, [%2]\n"
		"	cmp   %0, %3\n"
		"	bne   2f\n"
		"	strex %1, %4, [%2]\n"
		"	teq   %1, #0\n"
		"	bne   1b\n"
		"2:\n"
		: "=&r" (prev), "=&r" (tmp)
		: "r" (&a->val), "r" (oldVal), "r" (newVal)
		: "cc", "memory"
	);
	return prev;
}
#else
#error "FIXME: Implement CAS for this case"
#endif

#if defined(MOJ_X86)
inline MojInt32 MojAtomicAdd(MojAtomicT* a, MojInt32 incr)
{
	MojAssert(a);
	MojInt32 i = incr;
	asm volatile(
			"lock xaddl %0, %1"
				: "+r" (i), "+m" (a->val)
				: : "memory");
	return incr + i;
}
#elif defined(MOJ_ARM)
inline MojInt32 MojAtomicAdd(MojAtomicT* a, MojInt32 incr)
{
	MojAssert(a);
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 3)
	/* Use for GCC 4.4 and greater */
	return __sync_add_and_fetch(&a->val, incr);
#else
	/* Keep this in case we have to build using OE Classic */
	MojUInt32 tmp;
	MojInt32 res;
	asm volatile(
			"1:	ldrex %0, [%2]\n"
			"add %0, %0, %3\n"
			"strex %1, %0, [%2]\n"
			"teq %1, #0\n"
			"bne 1b"
				: "=&r" (res), "=&r" (tmp)
				: "r" (&a->val), "Ir" (incr)
				: "cc");
	return res;
#endif
}
#endif

inline MojInt32 MojAtomicIncrement(MojAtomicT* a)
{
	return MojAtomicAdd(a, 1);
}

inline MojInt32 MojAtomicDecrement(MojAtomicT* a)
{
	return MojAtomicAdd(a, -1);
}

#endif /* MOJOSLINUXINTERNAL_H_ */
