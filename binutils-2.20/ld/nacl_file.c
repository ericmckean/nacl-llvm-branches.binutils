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
#include <string.h>
#include <sys/mman.h>
#include <sys/nacl_syscalls.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <nacl/nacl_srpc.h>

#define FILE_TO_NACLFILE(f) file_to_naclfile((f), __FUNCTION__)

const int NACL_FILE_MAGIC = 0xfadefade;
const int NACL_INITIAL_BUFFER_SIZE = (16 * 1024);
#define NACL_MAX_FILES 128
#define MMAP_PAGE_SIZE 64 * 1024
#define MMAP_ROUND_MASK (MMAP_PAGE_SIZE - 1)


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
int NaClMapFileForReading(const char* filename,
                          NaClSrpcImcDescType shmem_fd,
                          int size);
int NaClLoadFileForReading(const char* filename, NaClSrpcImcDescType fd);

FILE* nacl_fopen(const char* filename, const char* mode) {
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


int nacl_fclose(FILE *stream) {
  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ fclose(%s) -> %d\n", nf->filename, nf->size);
  if (nf->mode[0] == 'w') {
#if defined(TEST_NACL_FILE_HOOKS)
    save_whole_file(nf);
#endif
  }
  nf->opened = 0;
  return 0;
}


int nacl_ferror(FILE *stream) {
  const NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ ferror(%s)\n", nf->filename);
  return nf->error;
}


void nacl_clearerr(FILE *stream) {
  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ clearerr(%s)\n", nf->filename);
  nf->error = 0;
  nf->eof = 0;
}


int nacl_feof(FILE *stream) {
  const NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ feof(%s)\n", nf->filename);
  return nf->eof;
}


void nacl_rewind(FILE *stream) {
  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ rewind(%s)\n", nf->filename);

  nf->pos = 0;
  nf->eof = 0;
  nf->error = 0;
}


size_t nacl_fread(void *ptr, size_t size, size_t nmemb, FILE* stream) {
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
  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ ftell(%s)\n", nf->filename);
  return nf->pos;
}


int nacl_fseek (FILE* stream, long offset, int whence) {
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
  NACL_FILE* nf = FILE_TO_NACLFILE(stream);
  debug(1, "@@ fflush(%s)\n", nf->filename);
  return 0;
}

#if defined(NACL_SRPC)

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
  return nf;
}

int NaClMapFileForReading(const char* filename,
                          NaClSrpcImcDescType shmem_fd,
                          int size) {
  debug(1, "@@ reading file (shmem) %s size: %d\n", filename, size);
  NACL_FILE* nf = find_nacl_read_file(filename, size);
  const int count_up = roundToNextPageSize(size);
  nf->data = (char *) mmap(NULL, count_up, PROT_READ, MAP_SHARED, shmem_fd, 0);
  return 0;
}

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

void NaClSetFileDebugLevel(int level) {
  global_debug_level = level;
}

#endif
