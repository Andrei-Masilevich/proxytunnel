project( proxytunnel )
cmake_minimum_required( VERSION 2.8.12 )

if (UNIX)
    find_package(OpenSSL QUIET)

    if (OpenSSL_FOUND)

        message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
        message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

        include_directories(${OPENSSL_INCLUDE_DIR})

    else()
        message(FATAL_ERROR "OpenSSL lib required")

    endif()

    set(PROXYTUNNEL_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/proxytunnel.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/base64.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/strzcat.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/setproctitle.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/io.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/http.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/basicauth.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/readpassphrase.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/messages.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmdline.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/globals.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/ntlm.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/digestauth.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/ptstream.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/strlcpy.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/strlcat.c"
    )
    file(GLOB PROXYTUNNEL_HEADERS
        "${CMAKE_CURRENT_SOURCE_DIR}/*.h")

    add_executable( proxytunnel
                ${PROXYTUNNEL_SOURCES}
                ${PROXYTUNNEL_HEADERS} )
    target_link_libraries( proxytunnel
                        ${OPENSSL_LIBRARIES})

    target_compile_definitions( proxytunnel PRIVATE -DHAVE_GETOPT_LONG)
    target_compile_definitions( proxytunnel PRIVATE -DUSE_SSL)
    target_compile_definitions( proxytunnel PRIVATE -DSETPROCTITLE)
    target_compile_definitions( proxytunnel PRIVATE -DSPT_TYPE=2)

else()

    MESSAGE( FATAL_ERROR  "Platform is not supported!" )

endif()
