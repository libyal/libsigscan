/*
 * Codepage definitions for libsigscan
 *
 * Copyright (C) 2014-2021, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#if !defined( _LIBSIGSCAN_CODEPAGE_H )
#define _LIBSIGSCAN_CODEPAGE_H

#include <libsigscan/types.h>

#if defined( __cplusplus )
extern "C" {
#endif

/* The codepage definitions
 */
enum LIBSIGSCAN_CODEPAGES
{
	LIBSIGSCAN_CODEPAGE_ASCII			= 20127,

	LIBSIGSCAN_CODEPAGE_ISO_8859_1			= 28591,
	LIBSIGSCAN_CODEPAGE_ISO_8859_2			= 28592,
	LIBSIGSCAN_CODEPAGE_ISO_8859_3			= 28593,
	LIBSIGSCAN_CODEPAGE_ISO_8859_4			= 28594,
	LIBSIGSCAN_CODEPAGE_ISO_8859_5			= 28595,
	LIBSIGSCAN_CODEPAGE_ISO_8859_6			= 28596,
	LIBSIGSCAN_CODEPAGE_ISO_8859_7			= 28597,
	LIBSIGSCAN_CODEPAGE_ISO_8859_8			= 28598,
	LIBSIGSCAN_CODEPAGE_ISO_8859_9			= 28599,
	LIBSIGSCAN_CODEPAGE_ISO_8859_10			= 28600,
	LIBSIGSCAN_CODEPAGE_ISO_8859_11			= 28601,
	LIBSIGSCAN_CODEPAGE_ISO_8859_13			= 28603,
	LIBSIGSCAN_CODEPAGE_ISO_8859_14			= 28604,
	LIBSIGSCAN_CODEPAGE_ISO_8859_15			= 28605,
	LIBSIGSCAN_CODEPAGE_ISO_8859_16			= 28606,

	LIBSIGSCAN_CODEPAGE_KOI8_R			= 20866,
	LIBSIGSCAN_CODEPAGE_KOI8_U			= 21866,

	LIBSIGSCAN_CODEPAGE_WINDOWS_874			= 874,
	LIBSIGSCAN_CODEPAGE_WINDOWS_932			= 932,
	LIBSIGSCAN_CODEPAGE_WINDOWS_936			= 936,
	LIBSIGSCAN_CODEPAGE_WINDOWS_949			= 949,
	LIBSIGSCAN_CODEPAGE_WINDOWS_950			= 950,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1250		= 1250,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1251		= 1251,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1252		= 1252,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1253		= 1253,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1254		= 1254,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1255		= 1255,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1256		= 1256,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1257		= 1257,
	LIBSIGSCAN_CODEPAGE_WINDOWS_1258		= 1258
};

#define LIBSIGSCAN_CODEPAGE_US_ASCII			LIBSIGSCAN_CODEPAGE_ASCII

#define LIBSIGSCAN_CODEPAGE_ISO_WESTERN_EUROPEAN	LIBSIGSCAN_CODEPAGE_ISO_8859_1
#define LIBSIGSCAN_CODEPAGE_ISO_CENTRAL_EUROPEAN	LIBSIGSCAN_CODEPAGE_ISO_8859_2
#define LIBSIGSCAN_CODEPAGE_ISO_SOUTH_EUROPEAN		LIBSIGSCAN_CODEPAGE_ISO_8859_3
#define LIBSIGSCAN_CODEPAGE_ISO_NORTH_EUROPEAN		LIBSIGSCAN_CODEPAGE_ISO_8859_4
#define LIBSIGSCAN_CODEPAGE_ISO_CYRILLIC		LIBSIGSCAN_CODEPAGE_ISO_8859_5
#define LIBSIGSCAN_CODEPAGE_ISO_ARABIC			LIBSIGSCAN_CODEPAGE_ISO_8859_6
#define LIBSIGSCAN_CODEPAGE_ISO_GREEK			LIBSIGSCAN_CODEPAGE_ISO_8859_7
#define LIBSIGSCAN_CODEPAGE_ISO_HEBREW			LIBSIGSCAN_CODEPAGE_ISO_8859_8
#define LIBSIGSCAN_CODEPAGE_ISO_TURKISH			LIBSIGSCAN_CODEPAGE_ISO_8859_9
#define LIBSIGSCAN_CODEPAGE_ISO_NORDIC			LIBSIGSCAN_CODEPAGE_ISO_8859_10
#define LIBSIGSCAN_CODEPAGE_ISO_THAI			LIBSIGSCAN_CODEPAGE_ISO_8859_11
#define LIBSIGSCAN_CODEPAGE_ISO_BALTIC			LIBSIGSCAN_CODEPAGE_ISO_8859_13
#define LIBSIGSCAN_CODEPAGE_ISO_CELTIC			LIBSIGSCAN_CODEPAGE_ISO_8859_14

#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_1			LIBSIGSCAN_CODEPAGE_ISO_8859_1
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_2			LIBSIGSCAN_CODEPAGE_ISO_8859_2
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_3			LIBSIGSCAN_CODEPAGE_ISO_8859_3
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_4			LIBSIGSCAN_CODEPAGE_ISO_8859_4
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_5			LIBSIGSCAN_CODEPAGE_ISO_8859_9
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_6			LIBSIGSCAN_CODEPAGE_ISO_8859_10
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_7			LIBSIGSCAN_CODEPAGE_ISO_8859_13
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_8			LIBSIGSCAN_CODEPAGE_ISO_8859_14
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_9			LIBSIGSCAN_CODEPAGE_ISO_8859_15
#define LIBSIGSCAN_CODEPAGE_ISO_LATIN_10		LIBSIGSCAN_CODEPAGE_ISO_8859_16

#define LIBSIGSCAN_CODEPAGE_KOI8_RUSSIAN		LIBSIGSCAN_CODEPAGE_KOI8_R
#define LIBSIGSCAN_CODEPAGE_KOI8_UKRAINIAN		LIBSIGSCAN_CODEPAGE_KOI8_U

#define LIBSIGSCAN_CODEPAGE_WINDOWS_THAI		LIBSIGSCAN_CODEPAGE_WINDOWS_874
#define LIBSIGSCAN_CODEPAGE_WINDOWS_JAPANESE		LIBSIGSCAN_CODEPAGE_WINDOWS_932
#define LIBSIGSCAN_CODEPAGE_WINDOWS_CHINESE_SIMPLIFIED	LIBSIGSCAN_CODEPAGE_WINDOWS_936
#define LIBSIGSCAN_CODEPAGE_WINDOWS_KOREAN		LIBSIGSCAN_CODEPAGE_WINDOWS_949
#define LIBSIGSCAN_CODEPAGE_WINDOWS_CHINESE_TRADITIONAL	LIBSIGSCAN_CODEPAGE_WINDOWS_950
#define LIBSIGSCAN_CODEPAGE_WINDOWS_CENTRAL_EUROPEAN	LIBSIGSCAN_CODEPAGE_WINDOWS_1250
#define LIBSIGSCAN_CODEPAGE_WINDOWS_CYRILLIC		LIBSIGSCAN_CODEPAGE_WINDOWS_1251
#define LIBSIGSCAN_CODEPAGE_WINDOWS_WESTERN_EUROPEAN	LIBSIGSCAN_CODEPAGE_WINDOWS_1252
#define LIBSIGSCAN_CODEPAGE_WINDOWS_GREEK		LIBSIGSCAN_CODEPAGE_WINDOWS_1253
#define LIBSIGSCAN_CODEPAGE_WINDOWS_TURKISH		LIBSIGSCAN_CODEPAGE_WINDOWS_1254
#define LIBSIGSCAN_CODEPAGE_WINDOWS_HEBREW		LIBSIGSCAN_CODEPAGE_WINDOWS_1255
#define LIBSIGSCAN_CODEPAGE_WINDOWS_ARABIC		LIBSIGSCAN_CODEPAGE_WINDOWS_1256
#define LIBSIGSCAN_CODEPAGE_WINDOWS_BALTIC		LIBSIGSCAN_CODEPAGE_WINDOWS_1257
#define LIBSIGSCAN_CODEPAGE_WINDOWS_VIETNAMESE		LIBSIGSCAN_CODEPAGE_WINDOWS_1258

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBSIGSCAN_CODEPAGE_H ) */

