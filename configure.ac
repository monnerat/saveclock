AC_PREREQ([2.57])
AC_INIT([saveclock], [0.2])
AC_CONFIG_SRCDIR([saveclock.c])
AM_INIT_AUTOMAKE

dnl	 Checks for programs.
AC_PROG_CC

dnl	 Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/time.h syslog.h unistd.h])

dnl	 Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

dnl	 Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm ftruncate memset strchr strerror strspn])

dnl     Define system directories.
AC_ARG_WITH([rundir],
	AS_HELP_STRING([--with-rundir=DIR],
		[directory for pid file [LOCALSTATEDIR/run]]),
	[RUNDIR=$withval],
	[RUNDIR='${localstatedir}/run'])
AC_SUBST([RUNDIR])
CFLAGS="${CFLAGS} -DRUNDIR=\\\"${RUNDIR}\\\""

AC_ARG_WITH([lockdir],
	AS_HELP_STRING([--with-lockdir=DIR],
		[directory for lock file [LOCALSTATEDIR/lock/subsys]]),
	[LOCKDIR=$withval],
	[LOCKDIR='${localstatedir}/lock/subsys'])
AC_SUBST([LOCKDIR])
CFLAGS="${CFLAGS} -DLOCKDIR=\\\"${LOCKDIR}\\\""

AC_ARG_WITH([storagedir],
	AS_HELP_STRING([--with-storagedir=DIR],
	    [directory for time storage file [LOCALSTATEDIR/lib/saveclock]]),
	[STORAGEDIR=$withval],
	[STORAGEDIR='${localstatedir}/lib/saveclock'])
AC_SUBST([STORAGEDIR])
AC_SUBST([storagedir], [${STORAGEDIR}])
CFLAGS="${CFLAGS} -DSTORAGEDIR=\\\"${STORAGEDIR}\\\""

dnl	Output target files.
AC_CONFIG_FILES([
	Makefile
	saveclock.spec
])
AC_OUTPUT
