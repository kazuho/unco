CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

PROJECT(unco)

SET(serial "0.1.0")
SET(soserial "1")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")
SET(BINDIR_REL "bin")
SET(LIBDIR_REL "lib")

ADD_LIBRARY(unco-preload SHARED src/preload.c src/log.c src/misc.c)
ADD_EXECUTABLE(unco src/cmd.c src/log.c src/misc.c src/sha1.c)

CONFIGURE_FILE(src/config.h.cmake src/config.h)

INSTALL(TARGETS unco unco-preload
	RUNTIME DESTINATION ${BINDIR_REL}
	LIBRARY DESTINATION ${LIBDIR_REL})
