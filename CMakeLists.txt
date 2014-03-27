CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

PROJECT(unco)
SET(serial "0.1.0")
SET(soserial "1")

SET(CMAKE_C_FLAGS_RELEASE "-Wall -g")

ADD_LIBRARY(unco-preload SHARED preload.c log.c misc.c)
ADD_EXECUTABLE(unco cmd.c log.c misc.c)
