CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

PROJECT(unco)

SET(serial "0.1.0")
SET(soserial "1")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")
SET(BINDIR_REL "bin")
SET(LIBDIR_REL "lib")
SET(MANDIR_REL "share/man")

INCLUDE_DIRECTORIES(third-party/kazutils.c third-party/sha1)

ADD_LIBRARY(unco-preload SHARED src/preload.c src/log.c src/misc.c third-party/kazutils.c/file.c third-party/kazutils.c/string.c)
ADD_EXECUTABLE(unco src/cmd.c src/log.c src/misc.c third-party/kazutils.c/file.c third-party/kazutils.c/list.c third-party/kazutils.c/string.c third-party/sha1/sha1.c)

CONFIGURE_FILE(src/config.h.cmake src/config.h)

IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	TARGET_LINK_LIBRARIES(unco-preload dl)
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

INSTALL(TARGETS unco unco-preload
	RUNTIME DESTINATION ${BINDIR_REL}
	LIBRARY DESTINATION ${LIBDIR_REL})
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/unco.1 DESTINATION ${MANDIR_REL}/man1)

ADD_CUSTOM_TARGET(test prove)

FIND_PROGRAM(POD2MAN NAMES pod2man5.12 pod2man)
ADD_CUSTOM_TARGET(man ${POD2MAN} --section=1 --center="LOCAL USER COMMANDS" --release ${serial} --name ${PROJECT_NAME} README.pod > ${CMAKE_CURRENT_BINARY_DIR}/unco.1)
