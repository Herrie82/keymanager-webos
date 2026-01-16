/* ARM Compatibility for GCC 4.3.3 (CodeSourcery 2009q1)
 * Provides atomic CAS implementation for older ARM toolchains
 */
#ifndef MOJ_ARM_COMPAT_H
#define MOJ_ARM_COMPAT_H

#ifdef MOJ_ARM

/* Forward declaration */
struct MojAtomicT;

/* ARM CAS implementation using ldrex/strex (ARMv6+)
 * Returns the old value at the location
 */
inline MojInt32 MojAtomicCAS(MojAtomicT* a, MojInt32 oldVal, MojInt32 newVal)
{
    MojInt32 prev, tmp;
    asm volatile(
        "1: ldrex %0, [%2]\n"       /* Load exclusive: prev = *a */
        "   cmp   %0, %3\n"         /* Compare prev with oldVal */
        "   bne   2f\n"             /* If not equal, exit */
        "   strex %1, %4, [%2]\n"   /* Store exclusive: *a = newVal */
        "   teq   %1, #0\n"         /* Test if store succeeded */
        "   bne   1b\n"             /* If not, retry */
        "2:\n"
        : "=&r" (prev), "=&r" (tmp)
        : "r" (&((MojAtomicT*)a)->val), "r" (oldVal), "r" (newVal)
        : "cc", "memory"
    );
    return prev;
}

#endif /* MOJ_ARM */

#endif /* MOJ_ARM_COMPAT_H */
