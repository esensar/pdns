AC_DEFUN([DNSDIST_WITH_MMDB], [
  AC_MSG_CHECKING([whether we will we linking with libmaxminddb])
  HAVE_MMDB=0
  AC_ARG_WITH([mmdb],
    AS_HELP_STRING([--with-mmdb], [use MaxmindDB @<:@default=auto@:>@]),
    [with_mmdb=$withval],
    [with_mmdb=auto]
  )
  AC_MSG_RESULT([$with_mmdb])

  AS_IF([test "x$with_mmdb" != "xno"], [
    AS_IF([test "x$with_mmdb" = "xyes" -o "x$with_mmdb" = "xauto"], [
      PKG_CHECK_MODULES([MMDB], [libmaxminddb], [
        [HAVE_MMDB=1]
        AC_DEFINE([HAVE_MMDB], [1], [Define to 1 if you have MMDB])
        ],
        [AC_CHECK_HEADERS([maxminddb.h],
          [AC_CHECK_LIB([maxminddb], [MMDB_open],
            [
              MMDB_CFLAGS="-I$with_maxminddb_incdir"
              MMDB_LIBS="-L$with_maxminddb_libdir -lmaxminddb"
              AC_DEFINE([HAVE_MMDB], [1], [Define to 1 if you have MMDB])
              [HAVE_MMDB=1]
            ],
            [:]
          )],
          [:]
        )]
      )
    ])
  ])
  AC_SUBST(MMDB_LIBS)
  AC_SUBST(MMDB_CFLAGS)
  AM_CONDITIONAL([HAVE_MMDB], [test "x$MMDB_LIBS" != "x"])
  AS_IF([test "x$with_mmdb" = "xyes"], [
    AS_IF([test x"$MMDB_LIBS" = "x"], [
      AC_MSG_ERROR([MaxmindDB requested but libraries were not found])
    ])
  ])
])
