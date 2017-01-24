/*
 * Codepage functions
 *
 * Copyright (C) 2014-2017, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined( _LIBSIGSCAN_INTERNAL_CODEPAGE_H )
#define _LIBSIGSCAN_INTERNAL_CODEPAGE_H

#include <common.h>
#include <types.h>

#if defined( __cplusplus )
extern "C" {
#endif

#if !defined( HAVE_LOCAL_LIBSIGSCAN )

#include <libsigscan/codepage.h>

/* Define HAVE_LOCAL_LIBSIGSCAN for local use of libsigscan
 * The definitions in <libsigscan/codepage.h> are copied here
 * for local use of libsigscan
 */
#else

/* The codepage definitions
 */
enum LIBSIGSCAN_CODEPAGES
{
	LIBSIGSCAN_CODEPAGE_ASCII		= 20127,

	LIBSIGSCAN_CODEPAGE_ISO_8859_1		= 28591,
	LIBSIGSCAN_CODEPAGE_ISO_8859_2		= 28592,
	LIBSIGSCAN_CODEPAGE_ISO_8859_3		= 28593,
	LIBSIGSCAN_CODEPAGE_ISO_8859_4		= 28594,
	LIBSIGSCAN_CODEPAGE_ISO_8859_5		= 28595,
	LIBSIGSCAN_CODEPAGE_ISO_8859_6		= 28596,
	LIBSIGSCAN_CODEPAGE_ISO_8859_7		= 28597,
	LIBSIGSCAN_CODEPAGE_ISO_8859_8		= 28598,
	LIBSIGSCAN_CODEPAGE_ISO_8859_9		= 28599,
	LIBSIGSCAN_CODEPAGE_ISO_8859_10		= 28600,
	LIBSIGSCAN_CODEPAGE_ISO_8859_11		= 28601,
	LIBSIGSCAN_CODEPAGE_ISO_8859_13		= 28603,
	LIBSIGSCAN_CODEPAGE_ISO_8859_14		= 28604,
	LIBSIGSCAN_CODEPAGE_ISO_8859_15		= 28605,
	LIBSIGSCAN_CODEPAGE_ISO_8859_16		= 28606,

	LIBSIGSCAN_CODEPAGE_KOI8_R		= 20866,
	LIBSIGSCAN_CODEPAGE_KOI8_U		= 21866,

	LIBSIGSCAN_CODEPAGE_WINDOWS_874		= 874,
	LIBSIGSCAN_CODEPAGE_WINDOWS_932		= 932,
	LIBSIGSCAN_CODEPAGE_WINDOWS_936		= 936,
	LIBSIGSCAN_CODEPAGE_WINDOWS_949		= 949,
	LIBSIGSCAN_CODEPAGE_WINDOWS_950		= 950,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1250	= 1250,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1251	= 1251,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1252	= 1252,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1253	= 1253,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1254	= 1254,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1255	= 1255,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1256	= 1256,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1257	= 1257,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1258	= 1258
};

#endif /* !defined( HAVE_LOCAL_LIBSIGSCAN ) */

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_INTERNAL_CODEPAGE_H ) */

