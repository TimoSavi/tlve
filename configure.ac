#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([tlve],[2.3-24],[tjsa@iki.fi])
AC_CONFIG_SRCDIR([src/tlve.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_AUX_DIR([config])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([foreign tar-pax])

AC_SUBST([VERSION])
ISODATE=`date +%Y-%m-%d`
AC_SUBST([ISODATE])

SHELL_CMD="/bin/sh"
AC_SUBST([SHELL_CMD])

AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([HOST],["$host"],[Host type.])
AC_DEFINE_UNQUOTED([BUILD_DATE],["$ISODATE"],[Build date.])
AC_DEFINE_UNQUOTED([SHELL_CMD],["$SHELL_CMD"],[Define to the shell for input preprocessing.])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
# HP-UX weirdness:
# Search for libiconv_open (not iconv_open) to discover if -liconv is needed!
AC_SEARCH_LIBS(libiconv_open, iconv)


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h features.h error.h errno.h getopt.h regex.h langinfo.h time.h libintl.h locale.h sys/time.h iconv.h signal.h sys/mman.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_SYS_LARGEFILE
AC_SYS_LONG_FILE_NAMES
AC_CHECK_TYPE([regex_t],[AC_DEFINE(HAVE_REGEX, 1, [Define to 1 if regex functions are available])],,[#if HAVE_REGEX_H
#include <regex.h>
#endif])
AC_CHECK_TYPES([iconv_t], [], [],[[#include <iconv.h>]])
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for JSON libraries (json-c or fastjson)
have_json=no
m4_ifdef([PKG_CHECK_MODULES], [
  PKG_CHECK_MODULES([JSON_C], [json-c], [
    have_json=yes
    AC_DEFINE([HAVE_JSON_C], [1], [Define to 1 if json-c is available])
    LIBS="$LIBS $JSON_C_LIBS"
  ], [
    PKG_CHECK_MODULES([FASTJSON], [libfastjson], [
      have_json=yes
      AC_DEFINE([HAVE_FASTJSON], [1], [Define to 1 if libfastjson is available])
      LIBS="$LIBS $FASTJSON_LIBS"
      JSON_C_CFLAGS="$FASTJSON_CFLAGS"
    ], [:])
  ])
])

if test "x${have_json}" = "xno"; then
  AC_SEARCH_LIBS([fjson_object_new_object], [fastjson], [
    have_json=yes
    AC_DEFINE([HAVE_FASTJSON], [1], [Define to 1 if libfastjson is available])
  ], [
    AC_SEARCH_LIBS([json_object_new_object], [json-c json], [
      have_json=yes
      AC_DEFINE([HAVE_JSON_C], [1], [Define to 1 if json-c is available])
    ], [
      AC_MSG_WARN([Neither json-c nor libfastjson found. JSON output support will be disabled.])
    ])
  ])
fi

AC_CHECK_HEADERS([libfastjson/json.h json-c/json.h json/json.h json.h])
if test "x${have_json}" = "xyes"; then
  AC_DEFINE([HAVE_JSON], [1], [Define to 1 if JSON library is available])
fi
AC_SUBST([JSON_C_CFLAGS])


# Checks for library functions.
AC_FUNC_STRFTIME
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([setmode strcasecmp strncasecmp strchr sigaction])  
AC_CHECK_FUNCS([strdup strerror strstr getline getopt_long regcomp setlocale nl_langinfo])  
AC_CHECK_FUNCS([strtoll strtoull atoll iconv_open dup2 pipe munmap madvise setvbuf isatty])  

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 examples/Makefile
                 src/Makefile
                 tests/Makefile])
AC_OUTPUT
