# Process this file with autoconf to produce a configure script.

# Sets up package and initializes build system.
AC_INIT([FilterFS], [0.1])
AC_CONFIG_SRCDIR([src/filterfs.c])
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([fuse], [fuse_main],, [AC_MSG_ERROR([You must have libfuse-dev installed to build filterfs.])])

# Checks for packages which use pkg-config.
PKG_CHECK_MODULES([fuse], [fuse >= 2.6.0])

# Large file support
AC_SYS_LARGEFILE

# Outputs resulting files.
AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
