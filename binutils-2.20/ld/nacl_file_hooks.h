/* Copyright (c) 2011 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#if defined(__native_client__) && !defined(NACL_SRPC)
 /* In the non-SRPC case, we don't have fcntl but bfdio.c uses it under 
    HAVE_FILENO instead of HAVE_FCNTL */
#undef HAVE_FILENO
#endif

#if (defined(__native_client__) && defined(NACL_SRPC)) \
    || defined(TEST_NACL_FILE_HOOKS)

/*
 * Just to be safe: undefine some macros for undesirable code paths
 * mostly in bfd/bfdio.h
 */
#undef HAVE_FDOPEN

#undef HAVE_FILENO

#undef HAVE_FSEEKO64
#undef HAVE_FSEEKO

#undef HAVE_FTELLO64
#undef HAVE_FTELLO
#undef HAVE_FOPEN64

/*
 * Some of these functions could be macros itself,
 * so we need to undefine them first.
 */
#undef feof
#undef ferror
#undef clearerr
#undef getc
#undef fflush

#define fopen(n,m)  nacl_fopen(n,m)
#define fclose(f) nacl_fclose(f)

#define ftell(f) nacl_ftell(f)
#define fseek(f,o,w) nacl_fseek(f,o,w)

#define fread(p,s,n,f) nacl_fread(p,s,n,f)
#define fwrite(p,s,n,f) nacl_fwrite(p,s,n,f)

#define feof(f) nacl_feof(f)
#define ferror(f) nacl_ferror(f)
#define rewind(f) nacl_rewind(f)

#define getc(f) nacl_fgetc(f)
#define fgetc(f) nacl_fgetc(f)
#define clearerr(f) nacl_clearerr(f)
#define fileno(f) -1
#define fflush(f) nacl_fflush(f)

/*
 * NOTE: we do not provide support for these yet as they are not used by ld
 *
 */

#undef putc
#define fputc FPUT_FGET_ETC_NOT_SUPPORTED
#define putc FPUT_FGET_ETC_NOT_SUPPORTED
#define fputs FPUT_FGET_ETC_NOT_SUPPORTED
#define fgets FPUT_FGET_ETC_NOT_SUPPORTED

#define fgetpos FPUT_FGET_ETC_NOT_SUPPORTED
#define fdopen FPUT_FGET_ETC_NOT_SUPPORTED

extern size_t nacl_ftell (FILE *file);
extern int nacl_fseek (FILE *file, size_t offset, int whence);
extern FILE *nacl_fopen (const char *filename, const char *modes);

extern size_t nacl_fread(void *ptr, size_t size, size_t nmemb,
                         FILE *stream);
extern size_t nacl_fwrite(const void *ptr, size_t size, size_t nmemb,
                          FILE *stream);
extern int nacl_fclose(FILE *fp);
extern int nacl_feof(FILE *stream);
extern int nacl_ferror(FILE *stream);
extern void nacl_rewind(FILE *stream);
extern int nacl_fgetc(FILE *stream);
extern int nacl_fflush(FILE *stream);
#endif