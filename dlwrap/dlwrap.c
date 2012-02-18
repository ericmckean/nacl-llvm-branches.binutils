#include <stdio.h>
#include <string.h>

/* This is a libdl emulation library which provides the statically-linked LLVM
 * gold plugin as if it were dynamically loaded.
 *
 * The only supported usage is the following:
 *
 *   void *plugin = dlopen("LLVMgold", RTLD_NOW);
 *   void *onload_function = dlsym(plugin, "onload");
 */


/* This must match RTLD_NOW in dlwrap.h */
#define RTLD_NOW   0x2

static int dummy;
static int haserr = 0;
static char errmsg[200];

/* This is not the real signature of this function,
 * but we just need the symbol address.
 */
void llvm_plugin_onload();

void *pnacl_dlopen(const char *filename, int flag) {
  void *ret;
  if (flag != 0 && flag != RTLD_NOW) {
    sprintf(errmsg, "Error: Unknown flag to pnacl_dlopen: %d\n", flag);
    haserr = 1;
    return NULL;
  }
  if (strstr(filename, "LLVMgold") == NULL) {
    sprintf(errmsg, "Error: Unexpected pnacl_dlopen: %s\n", filename);
    haserr = 1;
    return NULL;
  }
  return (void*)&dummy;
}

char *pnacl_dlerror(void) {
  if (haserr) {
    haserr = 0;
    return errmsg;
  }
  return NULL;
}

void *pnacl_dlsym(void *handle, const char *symbol) {
  if (handle != (void*)&dummy) {
    sprintf(errmsg, "Error: Unexpected pnacl_dlsym handle\n");
    haserr = 1;
    return NULL;
  }

  if (strcmp(symbol, "onload") != 0) {
    sprintf(errmsg, "Error: Unexpected pnacl_dlsym symbol: %s\n", symbol);
    haserr = 1;
    return NULL;
  }
  return (void*)&llvm_plugin_onload;
}

int pnacl_dlclose(void *handle) {
  return 0;
}
