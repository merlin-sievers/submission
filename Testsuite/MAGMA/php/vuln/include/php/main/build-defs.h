/*
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | https://www.php.net/license/3_01.txt                                 |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Stig Sæther Bakken <ssb@php.net>                             |
   +----------------------------------------------------------------------+
*/

#define CONFIGURE_COMMAND " './configure'  '--host=arm-linux-gnueabihf' '--build=x86_64' '--disable-all' '--enable-option-checking=fatal' '--prefix=/home/jaenich/Magma/magma/targets/php/vuln/' '--enable-exif' '--enable-phar' '--enable-mbstring' '--without-pcre-jit' '--disable-phpdbg' '--disable-cgi' '--with-pic' '--disable-zend-signals' 'build_alias=x86_64' 'host_alias=arm-linux-gnueabihf' 'ONIG_CFLAGS=-I/home/jaenich/Magma/magma/targets/php/repo/oniguruma/src' 'ONIG_LIBS=-L/home/jaenich/Magma/magma/targets/php/repo/oniguruma/src/.libs -l:libonig.a'"
#define PHP_ODBC_CFLAGS	""
#define PHP_ODBC_LFLAGS		""
#define PHP_ODBC_LIBS		""
#define PHP_ODBC_TYPE		""
#define PHP_OCI8_DIR			""
#define PHP_OCI8_ORACLE_VERSION		""
#define PHP_PROG_SENDMAIL	"/usr/sbin/sendmail"
#define PEAR_INSTALLDIR         ""
#define PHP_INCLUDE_PATH	".:"
#define PHP_EXTENSION_DIR       "/home/jaenich/Magma/magma/targets/php/vuln/lib/php/extensions/no-debug-non-zts-20201009"
#define PHP_PREFIX              "/home/jaenich/Magma/magma/targets/php/vuln"
#define PHP_BINDIR              "/home/jaenich/Magma/magma/targets/php/vuln/bin"
#define PHP_SBINDIR             "/home/jaenich/Magma/magma/targets/php/vuln/sbin"
#define PHP_MANDIR              "/home/jaenich/Magma/magma/targets/php/vuln/php/man"
#define PHP_LIBDIR              "/home/jaenich/Magma/magma/targets/php/vuln/lib/php"
#define PHP_DATADIR             "/home/jaenich/Magma/magma/targets/php/vuln/share/php"
#define PHP_SYSCONFDIR          "/home/jaenich/Magma/magma/targets/php/vuln/etc"
#define PHP_LOCALSTATEDIR       "/home/jaenich/Magma/magma/targets/php/vuln/var"
#define PHP_CONFIG_FILE_PATH    "/home/jaenich/Magma/magma/targets/php/vuln/lib"
#define PHP_CONFIG_FILE_SCAN_DIR    ""
#define PHP_SHLIB_SUFFIX        "so"
#define PHP_SHLIB_EXT_PREFIX    ""
