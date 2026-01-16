/* Compatibility shim for PmLogLib - minimal stub for build compatibility */
#ifndef PMLOGLIB_STUB_H
#define PMLOGLIB_STUB_H

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal PmLogLib definitions for Mojo framework build */
typedef void* PmLogContext;

#define PmLogGetContext(name, ctx) (void)0
#define PmLogMsg(ctx, level, flags, msgid, kv_count, ...) (void)0
#define PmLogError(ctx, msgid, kv_count, ...) (void)0
#define PmLogWarning(ctx, msgid, kv_count, ...) (void)0
#define PmLogInfo(ctx, msgid, kv_count, ...) (void)0
#define PmLogDebug(ctx, ...) (void)0

#ifdef __cplusplus
}
#endif

#endif /* PMLOGLIB_STUB_H */
