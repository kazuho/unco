CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

PROJECT(unco)

SET(serial "0.1.0")
SET(soserial "1")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")
SET(LIBDIR_REL "lib")

ADD_LIBRARY(unco-preload SHARED preload.c log.c misc.c)
ADD_EXECUTABLE(unco cmd.c log.c misc.c)

CONFIGURE_FILE(config.h.cmake ${CMAKE_SOURCE_DIR}/config.h)

INSTALL(TARGETS unco unco-preload
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION ${LIBDIR_REL})
