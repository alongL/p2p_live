# Process this file with autoconf to produce a configure script.
# Portions of this file were adapted from GIMP.

AC_PREREQ(2.54)

m4_define([tinyproxy_major_version], [1])
m4_define([tinyproxy_minor_version], [8])
m4_define([tinyproxy_micro_version], [3])
m4_define([tinyproxy_real_version],
          [tinyproxy_major_version.tinyproxy_minor_version.tinyproxy_micro_version])
m4_define([tinyproxy_version], [tinyproxy_real_version])

# For overriding the version string. Comment out if not needed.
# m4_define([tinyproxy_version], [1.8.2])

m4_define([tinyproxy_unstable],
          m4_if(m4_eval(tinyproxy_minor_version % 2), [1], [yes], [no]))
m4_define([tinyproxy_stable],
          m4_if(m4_eval(tinyproxy_minor_version % 2), [0], [yes], [no]))

AC_INIT([Tinyproxy], [tinyproxy_version],
	[https://banu.com/tinyproxy/],
	[tinyproxy])

AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([dist-bzip2])
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4macros])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

TINYPROXY_MAJOR_VERSION=tinyproxy_major_version
TINYPROXY_MINOR_VERSION=tinyproxy_minor_version
TINYPROXY_MICRO_VERSION=tinyproxy_micro_version
TINYPROXY_REAL_VERSION=tinyproxy_real_version
TINYPROXY_VERSION=tinyproxy_version
TINYPROXY_UNSTABLE=tinyproxy_unstable
AC_SUBST(TINYPROXY_MAJOR_VERSION)
AC_SUBST(TINYPROXY_MINOR_VERSION)
AC_SUBST(TINYPROXY_MICRO_VERSION)
AC_SUBST(TINYPROXY_REAL_VERSION)
AC_SUBST(TINYPROXY_VERSION)
AC_SUBST(TINYPROXY_UNSTABLE)

dnl Temporarily defined here until we get tinyproxy-version.h
AC_DEFINE(TINYPROXY_VERSION, "tinyproxy_version", [Tinyproxy version number])

# The symbol TINYPROXY_UNSTABLE is defined above for substitution in
# Makefiles and conditionally defined here as a preprocessor symbol
# and automake conditional.
if test "x$TINYPROXY_UNSTABLE" = "xyes"; then
  AC_DEFINE(TINYPROXY_UNSTABLE, 1,
            [Define to 1 if this is an unstable version of Tinyproxy])
fi
AM_CONDITIONAL(TINYPROXY_UNSTABLE, test "x$TINYPROXY_UNSTABLE" = "xyes")


dnl Check if we're compiling on a weird platform :)
AC_USE_SYSTEM_EXTENSIONS


dnl Set the domain name for find the statistics of tinyproxy
AH_TEMPLATE([TINYPROXY_STATHOST],
	[This controls remote proxy stats display.])
AC_ARG_WITH(stathost,
            [AC_HELP_STRING([--with-stathost=HOST], [Default status host])],
            [AC_DEFINE_UNQUOTED(TINYPROXY_STATHOST, "$withval")
	     TINYPROXY_STATHOST="$withval"],
	    [AC_DEFINE_UNQUOTED(TINYPROXY_STATHOST, "tinyproxy.stats")
	     TINYPROXY_STATHOST="tinyproxy.stats"])

AC_SUBST(TINYPROXY_STATHOST)

dnl Add compiler-specific optimization flags
TP_ARG_ENABLE(debug,
              [Enable debugging support code and methods (default is NO)],
              no)

dnl Check to see if the XTinyproxy header is to be included
AH_TEMPLATE([XTINYPROXY_ENABLE],
	    [Define if you want to have the peer's IP address included in a XTinyproxy header sent to the server.])
TP_ARG_ENABLE(xtinyproxy,
              [Include the X-Tinyproxy header (default is YES)],
              yes)

if test x"$xtinyproxy_enabled" = x"yes"; then
    AC_DEFINE(XTINYPROXY_ENABLE)
fi

dnl Include filtering for domain/URLs
AH_TEMPLATE([FILTER_ENABLE],
	    [Defined if you would like filtering code included.])
TP_ARG_ENABLE(filter,
              [Enable filtering of domains/URLS (default is YES)],
              yes)

if test x"$filter_enabled" = x"yes"; then
    ADDITIONAL_OBJECTS="$ADDITIONAL_OBJECTS filter.o"
    AC_DEFINE(FILTER_ENABLE)
fi

dnl Include support for upstream proxies?
AH_TEMPLATE([UPSTREAM_SUPPORT],
            [Include support for connecting to an upstream proxy.])
TP_ARG_ENABLE(upstream,
              [Enable upstream proxying (default is YES)],
              yes)
if test x"$upstream_enabled" = x"yes"; then
    AC_DEFINE(UPSTREAM_SUPPORT)
fi

dnl Include support for reverse proxy?
AH_TEMPLATE([REVERSE_SUPPORT],
            [Include support for reverse proxy.])
TP_ARG_ENABLE(reverse,
              [Enable reverse proxying (default is NO)],
              no)
if test x"$reverse_enabled" = x"yes"; then
    ADDITIONAL_OBJECTS="$ADDITIONAL_OBJECTS reverse-proxy.o"
    AC_DEFINE(REVERSE_SUPPORT)
fi

dnl Include the transparent proxy support
AH_TEMPLATE([TRANSPARENT_PROXY],
	    [Include support for using tinyproxy as a transparent proxy.])
TP_ARG_ENABLE(transparent,
              [Enable transparent proxying code (default is NO)],
              no)
if test x"$transparent_enabled" = x"yes"; then
   ADDITIONAL_OBJECTS="$ADDITIONAL_OBJECTS transparent-proxy.o"
   AC_DEFINE(TRANSPARENT_PROXY)
fi

dnl Check for broken regex library
TP_ARG_ENABLE(regexcheck,
              [Check for working regex library (default is YES)],
              yes)

# This is required to build test programs below
AC_PROG_CC

dnl
dnl Checks for libraries
dnl
AC_CHECK_LIB(socket, socket, , [AC_CHECK_LIB(socket, htonl)])

dnl Some systems (OpenServer 5) dislike -lsocket -lnsl, so we try to
dnl avoid -lnsl checks, if we already have the functions which are
dnl usually in libnsl

unset ac_cv_func_yp_get_default_domain
AC_CHECK_FUNC(yp_get_default_domain,
              tinyproxy_no_nsl_checks=yes,
              tinyproxy_no_nsl_checks=no)
unset ac_cv_func_yp_get_default_domain

if test x"$tinyproxy_no_nsl_checks" != x"yes"; then
    AC_CHECK_LIB(nsl, gethostname, , [AC_CHECK_LIB(nsl, gethostbyaddr)])
fi

AC_CHECK_LIB(resolv, inet_aton)

AC_PROG_CXX
AC_PROG_RANLIB
AM_PROG_CC_C_O

dnl
dnl Checks for headers
dnl
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([sys/ioctl.h sys/mman.h sys/resource.h \
		  sys/select.h sys/socket.h sys/time.h sys/uio.h \
		  sys/un.h arpa/inet.h netinet/in.h \
		  assert.h ctype.h errno.h fcntl.h grp.h io.h libintl.h \
		  netdb.h pwd.h regex.h signal.h stdarg.h stddef.h stdio.h \
		  sysexits.h syslog.h time.h wchar.h wctype.h mntent.h \
		  values.h])

dnl OpenBSD machines don't like having malloc included (even if it's present)
dnl as they expect you to use stdlib.h
case "$target" in
    *-openbsd*) ;;
    *)         AC_CHECK_HEADER(malloc.h);;
esac


dnl Checks for types
AC_TYPE_SIZE_T
AC_TYPE_PID_T
AC_UNP_CHECK_TYPE(uint8_t, unsigned char)
AC_UNP_CHECK_TYPE(int16_t, short)
AC_UNP_CHECK_TYPE(uint16_t, unsigned short)
AC_UNP_CHECK_TYPE(int32_t, int)
AC_UNP_CHECK_TYPE(uint32_t, unsigned int)
AC_UNP_CHECK_TYPE(ssize_t, int)
AC_UNP_CHECK_TYPE(socklen_t, unsigned int)
AC_UNP_CHECK_TYPE(in_addr_t, uint32_t)


dnl Checks for libary functions
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([gethostname inet_ntoa memchr memset select socket strcasecmp \
                strchr strdup strerror strncasecmp strpbrk strstr strtol])
AC_CHECK_FUNCS([isascii memcpy setrlimit ftruncate regcomp regexec])
AC_CHECK_FUNCS([strlcpy strlcat])


dnl Enable extra warnings
DESIRED_FLAGS="-fdiagnostics-show-option -Wall -Wextra -Wno-unused-parameter -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wfloat-equal -Wundef -Wformat=2 -Wlogical-op -Wmissing-include-dirs -Wformat-nonliteral -Wold-style-definition -Wpointer-arith -Waggregate-return -Winit-self -Wpacked -pedantic -Wc++-compat -Wno-long-long -Wno-overlength-strings -Wdeclaration-after-statement -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wcast-qual -Wcast-align -Wwrite-strings -Wp,-D_FORTIFY_SOURCE=2 -fno-common"

if test -n "${MAINTAINER_MODE_FALSE}"; then
   DESIRED_FLAGS="-Werror $DESIRED_FLAGS"
fi

for flag in $DESIRED_FLAGS; do
  AS_COMPILER_FLAG([$flag], [CFLAGS="$CFLAGS $flag"])
done

dnl Disable debugging if it's not specified
if test x"$debug_enabled" != x"yes" ; then
    CFLAGS="-DNDEBUG $CFLAGS"
fi

LDFLAGS="-Wl,-z,defs"

dnl
dnl Make sure we can actually handle the "--with-*" and "--enable-*" stuff.
dnl

dnl Handle the REGEX library
if test x"$ac_cv_func_regexec" != x"yes"; then
    AC_MSG_ERROR([Could not locate the regexec() function])
else
    if test x"$regexcheck_enabled" = x"yes" ; then
        AC_MSG_CHECKING([whether the system's regex library is broken])
        AC_CACHE_VAL(tinyproxy_cv_regex_broken,
                     [AC_TRY_RUN([
#if HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#if HAVE_REGEX_H
# include <regex.h>
#endif
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
int main(void)
{
	regex_t blah;
	if (regcomp(&blah, "foo.*bar", REG_NOSUB) != 0)
		exit(1);
	if (regexec(&blah, "foobar", 0, NULL, 0) != 0)
		exit(1);
	else
		exit(0);

	return 0;
}
                     ],
                     tinyproxy_cv_regex_broken=no,
                     tinyproxy_cv_regex_broken=yes,
                     tinyproxy_cv_regex_broken=yes)])

        AC_MSG_RESULT([$tinyproxy_cv_regex_broken])

        if test x"$tinyproxy_cv_regex_broken" = x"yes" ; then
            AC_MSG_ERROR([Your system's regexec() function is broken.])
        fi
    fi
fi

dnl
dnl Substitute the variables into the various Makefiles
dnl
AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LIBS)
AC_SUBST(ADDITIONAL_OBJECTS)

# Check for asciidoc
#AC_PATH_PROG(A2X, a2x, no)
#AM_CONDITIONAL(HAVE_A2X, test "x$A2X" != "xno")
#if test x"$A2X" = x"no"; then
#  AC_MSG_ERROR([Test for asciidoc failed. See the file 'INSTALL' for help.])
#fi

dnl
dnl DHT
dnl

DHT_CFLAGS="-I\$(top_srcdir)/src/dht"
DHT_LIBS="\$(top_builddir)/src/dht/libdht.a"
AC_SUBST(DHT_CFLAGS)
AC_SUBST(DHT_LIBS)

dnl ----------------------------------------------------------------------------
dnl
dnl  libb64

LIBB64_CFLAGS="-I\$(top_srcdir)/src/libb64"
LIBB64_LIBS="\$(top_builddir)/src/libb64/libb64.a"
AC_SUBST(LIBB64_CFLAGS)
AC_SUBST(LIBB64_LIBS)


dnl
dnl utp
dnl

LIBUTP_CFLAGS="-I\$(top_srcdir)/src"
LIBUTP_LIBS="\$(top_builddir)/src/libutp/libutp.a"
AC_SUBST(LIBUTP_CFLAGS)
AC_SUBST(LIBUTP_LIBS)


dnl
dnl  miniuupnp
dnl

LIBUPNP_CFLAGS="-I\$(top_srcdir)/src"
LIBUPNP_LIBS="\$(top_builddir)/src/miniupnp/libminiupnp.a"
AC_SUBST(LIBUPNP_CFLAGS)
AC_SUBST(LIBUPNP_LIBS)


dnl 
dnl natpmp
dnl

LIBNATPMP_CFLAGS="-I\$(top_srcdir)/src/libnatpmp/"
LIBNATPMP_LIBS="\$(top_builddir)/src/libnatpmp/libnatpmp.a"

AC_SUBST(LIBNATPMP_CFLAGS)
AC_SUBST(LIBNATPMP_LIBS)


LIBCURL_LIBS="-lcurl"
LIBEVENT_LIBS="-levent"
ZLIB_LIBS="-lz"

AC_SUBST(LIBCURL_LIBS)
AC_SUBST(LIBEVENT_LIBS)
AC_SUBST(ZLIB_LIBS)

LIBEVENT_CFLAGS= 
LIBCURL_CFLAGS="-I/usr/local/include"
CRYPTO_CFLAGS=
PTHREAD_CFLAGS="-pthread"
ZLIB_CFLAGS=
LIBM="-lm"

AC_SUBST(LIBEVENT_CFLAGS)
AC_SUBST(LIBCURL_CFLAGS)
AC_SUBST(CRYPTO_CFLAGS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(ZLIB_CFLAGS)
AC_SUBST(LIBM)

dnl ----------------------------------------------------------------------------
dnl
dnl file monitoring for the daemon

AC_ARG_WITH([inotify],
            [AS_HELP_STRING([--with-inotify], [Enable inotify support (default=auto)])],
            [WANT_INOTIFY=${withval}],
            [WANT_INOTIFY=auto])
HAVE_INOTIFY=0
AS_IF([test "x$WANT_INOTIFY" != "xno"],
      [AC_CHECK_HEADER([sys/inotify.h],
                       [AC_CHECK_FUNC([inotify_init],
                                      [HAVE_INOTIFY=1])],
                                      [AS_IF([test "x$WANT_INOTIFY" = "xyes"],
                                             [AC_MSG_ERROR("inotify not found!")])])])
AM_CONDITIONAL([USE_INOTIFY], [test "x$WANT_INOTIFY" != "xno" -a $HAVE_INOTIFY -eq 1])

AC_ARG_WITH([kqueue],
            [AS_HELP_STRING([--with-kqueue],[Enable kqueue support (default=auto)])],
            [WANT_KQUEUE=${withval}],
            [WANT_KQUEUE=auto])
HAVE_KQUEUE=0
AS_IF([test "x$WANT_KQUEUE" != "xno"],
      [AC_CHECK_HEADER([sys/event.h],
                       [AC_CHECK_FUNC([kqueue],
                                      [HAVE_KQUEUE=1])],
                                      [AS_IF([test "x$WANT_KQUEUE" = "xyes"],
                                             [AC_MSG_ERROR("kqueue not found!")])])])
AM_CONDITIONAL([USE_KQUEUE], [test "x$WANT_KQUEUE" != "xno" -a $HAVE_KQUEUE -eq 1])


AC_CHECK_HEADERS([sys/statvfs.h \
                  xfs/xfs.h])

dnl
dnl checking
dnl

CURL_MINIMUM=7.15.4
AC_SUBST(CURL_MINIMUM)
LIBEVENT_MINIMUM=2.0.10
AC_SUBST(LIBEVENT_MINIMUM)
ZLIB_MINIMUM=1.2.3
AC_SUBST(ZLIB_MINIMUM)

# crypto backends
OPENSSL_MINIMUM=0.9.7
AC_SUBST(OPENSSL_MINIMUM)
CYASSL_MINIMUM=3.0
AC_SUBST(CYASSL_MINIMUM)
POLARSSL_MINIMUM=0x01020000 # 1.2
AC_SUBST(POLARSSL_MINIMUM)


#PKG_CHECK_MODULES(LIBCURL, [libcurl >= $CURL_MINIMUM])
#PKG_CHECK_MODULES(LIBEVENT, [libevent >= $LIBEVENT_MINIMUM])
#PKG_CHECK_MODULES(ZLIB, [zlib >= $ZLIB_MINIMUM])


AC_ARG_WITH([crypto], AS_HELP_STRING([--with-crypto=PKG],
            [Use specified crypto library: auto (default), openssl, cyassl, polarssl]),
            [want_crypto=$withval], [want_crypto=auto])

AS_IF([test "x$want_crypto" = "xauto" -o "x$want_crypto" = "xopenssl"], [
       PKG_CHECK_MODULES(OPENSSL, [openssl >= $OPENSSL_MINIMUM],
                         [want_crypto="openssl"; CRYPTO_PKG="openssl"; CRYPTO_CFLAGS="$OPENSSL_CFLAGS"; CRYPTO_LIBS="$OPENSSL_LIBS"],
                         [AS_IF([test "x$want_crypto" = "xopenssl"],
                                [AC_MSG_ERROR([OpenSSL support requested, but library not found.])]
                                )]
                         )
       ])
AS_IF([test "x$want_crypto" = "xauto" -o "x$want_crypto" = "xcyassl"], [
       PKG_CHECK_MODULES(WOLFSSL, [wolfssl >= $CYASSL_MINIMUM],
                         [want_crypto="cyassl"; CRYPTO_PKG="cyassl"; CRYPTO_CFLAGS="$WOLFSSL_CFLAGS"; CRYPTO_LIBS="$WOLFSSL_LIBS"],
                         [PKG_CHECK_MODULES(CYASSL, [cyassl >= $CYASSL_MINIMUM],
                                            [want_crypto="cyassl"; CRYPTO_PKG="cyassl"; CRYPTO_CFLAGS="$CYASSL_CFLAGS"; CRYPTO_LIBS="$CYASSL_LIBS"],
                                            [AS_IF([test "x$want_crypto" = "xcyassl"],
                                                   [AC_MSG_ERROR([CyaSSL support requested, but library not found.])]
                                                   )]
                                            )]
                         )
       ])
AS_IF([test "x$want_crypto" = "xauto" -o "x$want_crypto" = "xpolarssl"], [
       AC_CHECK_HEADER([polarssl/version.h],
                       [AC_EGREP_CPP([version_ok], [#include <polarssl/version.h>
                        #if defined (POLARSSL_VERSION_NUMBER) && POLARSSL_VERSION_NUMBER >= $POLARSSL_MINIMUM
                        version_ok
                        #endif],
                        [AC_CHECK_LIB([polarssl], [dhm_calc_secret],
                                      [want_crypto="polarssl"; CRYPTO_PKG="polarssl"; CRYPTO_CFLAGS=""; CRYPTO_LIBS="-lpolarssl"],
                                      [AS_IF([test "x$want_crypto" = "xpolarssl"],
                                             [AC_MSG_ERROR([PolarSSL support requested, but library not found.])]
                                             )]
                                      )],
                                      [AS_IF([test "x$want_crypto" = "xpolarssl"],
                                             [AC_MSG_ERROR([PolarSSL support requested, but version not suitable.])]
                                             )]
                                      )],
                                      [AS_IF([test "x$want_crypto" = "xpolarssl"],
                                             [AC_MSG_ERROR([PolarSSL support requested, but headers not found.])]
                                             )]
                                      )
       ])
# we should have found the library by now
AS_IF([test "x$CRYPTO_PKG" = "x"], [
       AS_IF([test "x$want_crypto" = "xauto"],
             [AC_MSG_ERROR([Unable to find any supported crypto library.])],
             [AC_MSG_ERROR([Requested crypto library "$want_crypto" is not supported.])],
             )
       ])

AM_CONDITIONAL([CRYPTO_USE_OPENSSL],[test "x$CRYPTO_PKG" = "xopenssl"])
AM_CONDITIONAL([CRYPTO_USE_CYASSL],[test "x$CRYPTO_PKG" = "xcyassl"])
AM_CONDITIONAL([CRYPTO_USE_POLARSSL],[test "x$CRYPTO_PKG" = "xpolarssl"])
AC_SUBST(CRYPTO_PKG)
AC_SUBST(CRYPTO_CFLAGS)
AC_SUBST(CRYPTO_LIBS)


LIBTOOL=libtool
AC_SUBST(LIBTOOL)

AC_SUBST(INTLLIBS)
AC_SUBST(PTHREAD_LIBS)


AC_CONFIG_FILES([
Makefile
src/Makefile
src/dht/Makefile
src/libb64/Makefile
src/libnatpmp/Makefile
src/libutp/Makefile
src/miniupnp/Makefile
src/libtransmission/Makefile
data/Makefile
data/templates/Makefile
etc/Makefile
m4macros/Makefile
tests/Makefile
tests/scripts/Makefile
])

AC_OUTPUT
