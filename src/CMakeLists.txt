include_directories(${GNUTLS_INCLUDE_DIR})
include_directories(${LIBTASN1_INCLUDE_DIR})

add_executable(parsemscat
               parsemscat.c)

target_link_libraries(parsemscat
                      ${GNUTLS_LIBRARIES}
                      ${LIBTASN1_LIBRARIES})

configure_file(mscat.asn ${CMAKE_CURRENT_BINARY_DIR}/mscat.asn COPYONLY)
