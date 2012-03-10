/* Copyright (c) 2011 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.

 * This file provides wrappers for most of the FILE* related functions
 * such a fopen/fclose/fread/fwrite.
 * Use this with the nacl_file_hooks.h header to "hijack" file operations.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#ifdef NACL_SRPC
#include <sys/nacl_syscalls.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

#ifdef NACL_SRPC
#include <nacl/nacl_srpc.h>
#endif

#define FILE_TO_NACLFILE(f) file_to_naclfile((f), __FUNCTION__)

const int NACL_FILE_MAGIC = 0xfadefade;
const int NACL_INITIAL_BUFFER_SIZE = (16 * 1024);
#define NACL_MAX_FILES    128
#define NACL_MAX_SONAMES  128
#define MMAP_PAGE_SIZE 64 * 1024
#define MMAP_ROUND_MASK (MMAP_PAGE_SIZE - 1)

/* This has to be enabled explicitly in ld. */
int NACL_FILE_ENABLED = 0;

/* These macros should be at the top of every nacl_* wrapper function.
   If NACL_FILE_ENABLE is false, they will be invoked instead. */
#define PASSTHROUGH_WITH_RETURN(_expr) \
  if (!NACL_FILE_ENABLED) { return _expr; }

#define PASSTHROUGH_VOID_RETURN(_statement) \
  if (!NACL_FILE_ENABLED) { _statement; return; }

int global_debug_level = 0;

static void debug(int level, const char* fmt, ...) {
  va_list argp;
  if (global_debug_level < level) return;
  va_start(argp, fmt);
  vprintf(fmt, argp);
  va_end(argp);
}

static void fatal(const char* fmt, ...) {
  va_list argp;
  va_start(argp, fmt);
  vprintf(fmt, argp);
  va_end(argp);
  exit(1);
}

static size_t roundToNextPageSize(size_t size) {
  size_t count_up = size + (MMAP_ROUND_MASK);
  return (count_up & ~(MMAP_ROUND_MASK));
}


typedef struct {
  int magic;
  const char* filename;
  const char* mode;
  size_t size;
  size_t alloc_size;
  size_t pos;
  char* data;
  int error;
  int eof;
  int opened;
} NACL_FILE;


/* zero intialized */
static NACL_FILE GlobalAllFiles[NACL_MAX_FILES];


static NACL_FILE* file_to_naclfile(FILE* stream, const char* function) {
  NACL_FILE* nf = (NACL_FILE*) stream;
  if( nf->magic != NACL_FILE_MAGIC) {
    fatal("invalid stream pointer in %s\n", function);
  }
  return nf;
}

#if !defined(NACL_SRPC)
static void load_whole_file(NACL_FILE* nf) {
  FILE* fp;
  fp = fopen(nf->filename, nf->mode);
  if (!fp) {
    fatal("%s: file open failed\n", nf->filename);
  }
  fseek(fp, 0, SEEK_END);
  nf->size = (size_t) ftell(fp);
  nf->alloc_size = nf->size;
  nf->data = malloc(nf->size);
  nf->pos = 0;
  fseek(fp, 0, SEEK_SET);
  fread(nf->data, 1, nf->size, fp);
  fclose(fp);
}


static void save_whole_file(NACL_FILE* nf) {
  FILE* fp;
  fp = fopen(nf->filename, nf->mode);
  fwrite(nf->data, 1, nf->size, fp);
  fclose(fp);
}
#endif

static NACL_FILE* find_unused_descriptor() {
  int i;
  for(i = 0; i < NACL_MAX_FILES; ++i) {
    if (GlobalAllFiles[i].filename == NULL) {
      return &GlobalAllFiles[i];
    }
  }
  return NULL;
}


static NACL_FILE* find_descriptor_by_name(const char* filename) {
  int i;
  for(i = 0; i < NACL_MAX_FILES; ++i) {
    if (GlobalAllFiles[i].filename == NULL) continue;
    if (0 == strcmp(GlobalAllFiles[i].filename, filename)) {
      return &GlobalAllFiles[i];
    }
  }
  return NULL;
}

extern int NaClLookupFileByName(const char* filename);

/* Add a virtual read-only file backed by memory 'data' with size 'size' */
void AddFileForReading(const char* filename,
                       const char *data,
                       int size);
#ifdef NACL_SRPC
int NaClMapFileForReading(const char* filename,
                          NaClSrpcImcDescType shmem_fd,
                          int size);
int NaClLoadFileForReading(const char* filename, NaClSrpcImcDescType fd);
#endif

FILE* nacl_fopen(const char* filename, const char* mode) {
  PASSTHROUGH_WITH_RETURN(fopen(filename, mode));

  debug(1, "@@nacl_fopen(%s,%s)\n", filename, mode);
#if defined(NACL_SRPC)
  if (mode[0] == 'r') {
    NACL_FILE* nf = find_descriptor_by_name(filename);
    if (nf == NULL) {
      /* Ask the coordinator for the descriptor/size for filename. */
      int fd = NaClLookupFileByName(filename);
      if (fd == -1) {
        debug(1, "cannot find preloaded %s\n", filename);
        return NULL;
      }
      if (0 != NaClLoadFileForReading(filename, fd)) {
        debug(1, "cannot load file %s\n", filename);
        return NULL;
      }
      nf = find_descriptor_by_name(filename);
    }
    return (FILE*)nf;
  }
#endif

  /* See if there is an existing file map for a read-only file.
     e.g. from a file inside the metadata file. */
  if (mode[0] == 'r') {
    NACL_FILE* nf = find_descriptor_by_name(filename);
    if (nf && nf->opened == 0) {
      nf->pos = 0;
      nf->opened = 1;
      return nf;
    }
  }

  /* If not, open it for real. */
  NACL_FILE* nf = find_unused_descriptor();
  nf->filename = strdup(filename);
  nf->mode = strdup(mode);
  nf->magic = NACL_FILE_MAGIC;
  switch (mode[0]) {
   default:
    return 0;
#if !defined(NACL_SRPC)
   case 'r':
    load_whole_file(nf);
    return (FILE*) nf;
#endif
   case 'w':
    /* use calloc because we may skip over areas which are never
       explicitely written via fseek. */
    nf->data = calloc(NACL_INITIAL_BUFFER_SIZE, 1);
    nf->alloc_size = NACL_INITIAL_BUFFER_SIZE;
    nf->size = 0;
    nf->pos = 0;
    break;
  }
  nf->opened = 1;
  return (FILE*)nf;
}

/* Keep this structure a multiple of 8-bytes
   This must match the same structure in llc.cpp */
typedef struct {
  uint32_t magic;        /* NACL_FILE_MAGIC */
  uint32_t size;         /* Size of this file */
  char     filename[64]; /* Padded with nulls */
} FileEntry;

/* The metadata file is actually a set of files (like an archive) */
/* This makes each individual file available by filename from nacl_fopen */
/* And also emits a list of sonames (filenames) */
void ExpandMetadataFile(const char *filename,
                        char ***sonames_out,
                        size_t *sonames_count_out) {
  char **sonames;
  size_t sonames_count;
  debug(1, "@@ExpandMetadataFile(%s)\n", filename);
  NACL_FILE* nf = FILE_TO_NACLFILE(nacl_fopen(filename, "r"));

  sonames_count = 0;
  sonames = (char**)malloc(sizeof(char*) * NACL_MAX_SONAMES);
  if (!sonames)
    fatal("allocation failed\n");

  if (sizeof(FileEntry) % 8 != 0)
    fatal("metadata data is not aligned");

  const char *p = nf->data;
  const char *endp = nf->data + nf->size;
  while (p < endp) {
    uint32_t offset_to_next;
    const FileEntry *FE = (FileEntry*)p;
    if (((uintptr_t)p) % 8 != 0)
      fatal("metadata file pointer has become misaligned!\n");
    if (FE->magic != NACL_FILE_MAGIC)
      fatal("metadata file magic doesn't match\n");
    char *data_start = p + sizeof(FileEntry);
    if (data_start + FE->size > endp)
      fatal("metadata file ended prematurely\n");
    if (FE->filename[sizeof(FE->filename) - 1] != '\0')
      fatal("metadata filename is not null-terminated");

    AddFileForReading(FE->filename, data_start, FE->size);
    /* This points inside the file data for the metadata file.
       So it should survive the entire ld call. (unless the
       NACL_FILE and associated data are freed) */
    if (sonames_count >= NACL_MAX_SONAMES)
      fatal("Exceeded NACL_MAX_SONAMES\n");
    sonames[sonames_count++] = FE->filename;

    /* Align up to 8-bytes. */
    offset_to_next = sizeof(FileEntry) + FE->size;
    offset_to_next = 8*((offset_to_next + 7)/8);
    p += offset_to_next;
  }
  if (p != endp)
    fatal("junk at the end of metadata file");
  *sonames_out = sonames;
  *sonames_count_out = sonames_count;
}

int nacl_fclose(FILE *stream) {
  PASSTHROUGH_WITH_RETURN(fclose(stream));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ fclose(%s) -> %d (mode %s)\n", nf->filename, nf->size, nf->mode);
  if (nf->mode[0] == 'w') {
#if !defined(NACL_SRPC)
    save_whole_file(nf);
#endif
  }
  nf->opened = 0;
  return 0;
}

int nacl_ferror(FILE *stream) {
  PASSTHROUGH_WITH_RETURN(ferror(stream));

  const NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ ferror(%s)\n", nf->filename);
  return nf->error;
}


void nacl_clearerr(FILE *stream) {
  PASSTHROUGH_VOID_RETURN(clearerr(stream));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ clearerr(%s)\n", nf->filename);
  nf->error = 0;
  nf->eof = 0;
}


int nacl_feof(FILE *stream) {
  PASSTHROUGH_WITH_RETURN(feof(stream));

  const NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ feof(%s)\n", nf->filename);
  return nf->eof;
}


void nacl_rewind(FILE *stream) {
  PASSTHROUGH_VOID_RETURN(rewind(stream));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ rewind(%s)\n", nf->filename);

  nf->pos = 0;
  nf->eof = 0;
  nf->error = 0;
}


size_t nacl_fread(void *ptr, size_t size, size_t nmemb, FILE* stream) {
  PASSTHROUGH_WITH_RETURN(fread(ptr, size, nmemb, stream));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ fread(%s, %uz, %uz)\n", nf->filename, size, nmemb);
  size_t total_size = size * nmemb;
  if (nf->pos + total_size > nf->size) {
    nf->eof = 1;
    total_size = nf->size - nf->pos;
  }

  memmove(ptr, nf->data + nf->pos, total_size);
  nf->pos += total_size;
  debug(1, "@@ fread -> %d\n", total_size / size);
  return total_size / size;
}


size_t nacl_fwrite(void *ptr, size_t size, size_t nmemb, FILE* stream) {
  PASSTHROUGH_WITH_RETURN(fwrite(ptr, size, nmemb, stream));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ fwrite(%s, %uz, %uz)\n", nf->filename, size, nmemb);
  const size_t total_size = size * nmemb;
  const size_t end_pos = nf->pos + total_size;
  if (end_pos > nf->alloc_size) {
    const int new_alloc_size = 2 * end_pos;
    nf->data = realloc(nf->data, new_alloc_size);
    if (nf->data == NULL) {
      fatal("ERROR realloc failed\n");
    }
    memset(nf->data + nf->alloc_size, 0,
           new_alloc_size -  nf->alloc_size);
    nf->alloc_size = new_alloc_size;
  }

  memmove(nf->data + nf->pos, ptr, total_size);
  nf->pos += total_size;
  if (nf->pos > nf->size) {
    nf->size = nf->pos;
  }
  return nmemb;
}


size_t nacl_ftell (FILE *stream) {
  PASSTHROUGH_WITH_RETURN(ftell(stream));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ ftell(%s)\n", nf->filename);
  return nf->pos;
}


int nacl_fseek (FILE* stream, long offset, int whence) {
  PASSTHROUGH_WITH_RETURN(fseek(stream, offset, whence));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ fseek(%s, %ld, %d)\n", nf->filename, offset, whence);
  switch (whence) {
    case SEEK_SET:
      break;
    case SEEK_CUR:
      offset = nf->pos + offset;
      break;
    case SEEK_END:
      offset = nf->size + offset;
      break;
  }

  if (offset < 0) {
    return -1;
  }

  /* NOTE: the emulation of fseek is not 100% compatible */
  nf->eof = 0;
  nf->pos = offset;
  return 0;
}


int nacl_fgetc(FILE* stream) {
  PASSTHROUGH_WITH_RETURN(fgetc(stream));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ fgetc(%s)\n", nf->filename);
  if (nf->pos >= nf->size) {
    nf->eof = 1;
    return EOF;
  }

  int result =  nf->data[nf->pos];
  nf->pos += 1;
  return result;
}


int nacl_fflush(FILE* stream) {
  PASSTHROUGH_WITH_RETURN(fflush(stream));

  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ fflush(%s)\n", nf->filename);
  return 0;
}

static NACL_FILE* find_nacl_read_file(const char* filename,
                                      size_t size) {
  NACL_FILE* nf = find_unused_descriptor();
  nf->filename = strdup(filename);
  nf->mode = "r";
  nf->magic = NACL_FILE_MAGIC;
  nf->pos = 0;
  nf->size = size;
  nf->alloc_size = size;
  nf->pos = 0;
  nf->data = NULL;
  nf->opened = 0;
  return nf;
}

/* Add a virtual read-only file backed by memory 'data' with size 'size' */
void AddFileForReading(const char* filename,
                       const char *data,
                       int size) {
  debug(1, "@@ AddFileForReading(%s, %p, %d)\n", filename, data, size);
  NACL_FILE* nf = find_nacl_read_file(filename, size);
  nf->data = (char*)data;
}

#ifdef NACL_SRPC
int NaClMapFileForReading(const char* filename,
                          NaClSrpcImcDescType shmem_fd,
                          int size) {
  debug(1, "@@ reading file (shmem) %s size: %d\n", filename, size);
  NACL_FILE* nf = find_nacl_read_file(filename, size);
  const int count_up = roundToNextPageSize(size);
  nf->data = (char *) mmap(NULL, count_up, PROT_READ, MAP_SHARED, shmem_fd, 0);
  return 0;
}
#endif

#ifdef NACL_SRPC
int NaClLoadFileForReading(const char* filename, NaClSrpcImcDescType fd) {
  struct stat stb;
  size_t size;

  if (0 != fstat(fd, &stb)) {
    fatal("cannot fstat %s\n", filename);
  }
  size = stb.st_size;
  debug(1, "@@ reading file (file) %s size: %uz\n", filename, size);
  NACL_FILE* nf = find_nacl_read_file(filename, size);
  nf->data = malloc(size);
  read(fd, nf->data, size);
  return 0;
}
#endif

/* This doesn't seem to be used anymore. */
#if 0
int NaClMakeFileAvailableViaShmem(const char* filename,
                                  NaClSrpcImcDescType* shmem_fd,
                                  int32_t* size) {
  NACL_FILE* nf = find_descriptor_by_name(filename);
  if (nf == NULL) {
    fatal("cannot find %s\n", filename);
  }

  debug(1, "@@ writing file %s size: %d\n", filename, nf->size);

  const int count_up = roundToNextPageSize(nf->size);
  const int fd = imc_mem_obj_create(count_up);
  if (fd < 0) {
    fatal("imc_mem_obj_create failed\n");
  }

  char* buf = (char*) mmap(NULL, count_up, PROT_WRITE, MAP_SHARED, fd, 0);
  if (NULL == buf) {
    fatal("ERROR: cannot map shm for write\n");
  }

  memcpy(buf, nf->data, nf->size);
  munmap(buf, count_up);
  *shmem_fd = fd;
  *size = nf->size;
  return 0;
}
#endif

#ifdef NACL_SRPC
int NaClFlushFileToFd(const char* filename, NaClSrpcImcDescType fd) {
  NACL_FILE* nf = find_descriptor_by_name(filename);
  if (nf == NULL) {
    fatal("cannot find %s\n", filename);
  }

  debug(1, "@@ writing file %s size: %d\n", filename, nf->size);

  if (fd < 0) {
    fatal("invalid fd\n");
  }

  size_t bytes_to_write = nf->size;
  const char* buf = nf->data;
  while (bytes_to_write > 0) {
    ssize_t bytes_written = write(fd, (const void*) buf, bytes_to_write);
    if (bytes_written < 0) {
      fatal("write failed\n");
    }
    buf += bytes_written;
    bytes_to_write -= (size_t) bytes_written;
  }

  return 0;
}
#endif

void NaClSetFileDebugLevel(int level) {
  global_debug_level = level;
}
