dnl Function to detect if libsigscan dependencies are available
AC_DEFUN([AX_LIBSIGSCAN_CHECK_LOCAL],
 [dnl Check for internationalization functions in libsigscan/libsigscan_i18n.c 
 AC_CHECK_FUNCS([bindtextdomain])
 ])

