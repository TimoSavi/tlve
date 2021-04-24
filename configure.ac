#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([tlve], [2.3], [tjsa@iki.fi])
AC_CONFIG_SRCDIR([src/tlve.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_AUX_DIR([config])
AC_GNU_SOURCE
AM_INIT_AUTOMAKE([foreign])

AC_SUBST([VERSION])
ISODATE=`date +%Y-%m-%d`
AC_SUBST([ISODATE])

SHELL_CMD="/bin/sh"
AC_SUBST([SHELL_CMD])

AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([HOST],["$host"],[Host type.])
AC_DEFINE_UNQUOTED([BUILD_DATE],["$ISODATE"],[Build date.])
AC_DEFINE_UNQUOTED([SHELL_CMD],["$SHELL_CMD"],[Define to the shell for input preprosessing.])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
# HP-UX weirdness:
# Search for libiconv_open (not iconv_open) to discover if -liconv is needed!
AC_SEARCH_LIBS(libiconv_open, iconv)


# Checks for header files.
jm_CHECK_TYPE_STRUCT_UTIMBUF
AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h features.h error.h errno.h getopt.h regex.h langinfo.h time.h libintl.h locale.h sys/time.h iconv.h signal.h])

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


# Checks for library functions.
AC_FUNC_STRFTIME
AC_FUNC_FORK
AC_CHECK_FUNCS([setmode strcasecmp strncasecmp strchr sigaction])  
AC_CHECK_FUNCS([strdup strerror strstr getline getopt_long regcomp setlocale nl_langinfo])  
AC_CHECK_FUNCS([strtoll strtoull atoll iconv_open dup2 pipe])  

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 examples/Makefile
                 src/Makefile])
AC_OUTPUT
