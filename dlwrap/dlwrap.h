/* This header is a drop-in replacement for dlfcn.h */
/* See dlwrap.c for more information */

#ifndef __DLWRAP_H
#define __DLWRAP_H

#ifdef ENABLE_DLWRAP

#define RTLD_NOW  0x2

#ifdef __cplusplus
extern "C" {
#endif

void *pnacl_dlopen(const char *filename, int flag);
char *pnacl_dlerror(void);
void *pnacl_dlsym(void *handle, const char *symbol);
int pnacl_dlclose(void *handle);

#ifdef __cplusplus
}
#endif

#define dlopen   pnacl_dlopen
#define dlerror  pnacl_dlerror
#define dlsym    pnacl_dlsym
#define dlclose  pnacl_dlclose

#endif /* ENABLE_DLWRAP */
#endif /* __DLWRAP_H */
