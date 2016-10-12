# - Try to find Libtasn1
# Once done this will define
#
#  LIBTASN1_FOUND - system has Libtasn1
#  LIBTASN1_INCLUDE_DIR - the Libtasn1 include directory
#  LIBTASN1_LIBRARIES - Link these to use Libtasn1
#  LIBTASN1_DEFINITIONS - Compiler switches required for using Libtasn1
#
#=============================================================================
#  Copyright (c) 2016 Andreas Schneider <asn@samba.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

if (UNIX)
  find_package(PkgConfig)
  if (PKG_CONFIG_FOUND)
    pkg_check_modules(_LIBTASN1 libtasn1)
  endif (PKG_CONFIG_FOUND)
endif (UNIX)

find_path(LIBTASN1_INCLUDE_DIR
    NAMES
        libtasn1.h
    PATHS
        ${_LIBTASN1_INCLUDEDIR}
)

find_library(TASN1_LIBRARY
    NAMES
        tasn1
    PATHS
        ${_LIBTASN1_LIBDIR}
)

if (TASN1_LIBRARY)
    set(LIBTASN1_LIBRARIES
        ${LIBTASN1_LIBRARIES}
        ${TASN1_LIBRARY}
    )
endif (TASN1_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libtasn1 DEFAULT_MSG LIBTASN1_LIBRARIES LIBTASN1_INCLUDE_DIR)

# show the LIBTASN1_INCLUDE_DIR and LIBTASN1_LIBRARIES variables only in the advanced view
mark_as_advanced(LIBTASN1_INCLUDE_DIR LIBTASN1_LIBRARIES)

