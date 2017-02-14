# CMakeLists files in this project can refer to the root source directory of
# the project as ${FLEA_SOURCE_DIR} and to the root binary directory of
# the project as ${FLEA_BINARY_DIR}.
cmake_minimum_required(VERSION 2.8)

SET (CMAKE_C_COMPILER   "clang")
SET (CMAKE_CXX_COMPILER "clang++")

#note: use correct gcc version /usr/bin/gcc
PROJECT(CertFuzzer)

# include standard cmake modules
INCLUDE(FindThreads)
#INCLUDE(FindQt4)

# Allow empty ELSE() and ENDIF() constructs
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)
# gnu-compiler flags

# Version info
SET(MAJOR_VERSION 0)
SET(MINOR_VERSION 1)
SET(PATCH_VERSION 0)

SET(CMAKE_C_FLAGS "-std=c99 -pedantic")


ADD_DEFINITIONS( 
      #-finline-functions -O3  -fomit-frame-pointer  -momit-leaf-frame-pointer 
     -g
     -std=c++11
     -fstrict-aliasing
     -W -Wall  -Wno-long-long
     -Wno-sign-compare -Wno-unused-parameter -Wno-unused-label -Wno-cast-qual
     -Wno-char-subscripts 
     -Wunused-function   -Wunused-value -Wunused-variable
     -Wpointer-arith  -Wcast-align -Wwrite-strings
  #out: -Wconversion 
  )
#-fsanitize=memory -fsanitize-memory-track-origins
# SET (CMAKE_CXX_FLAGS "-fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize=undefined -fno-sanitize-recover=undefined -fsanitize=bool,signed-integer-overflow,shift,vptr")

#ADD_DEFINITIONS(-DFLEA_PLTF_X86)
#ADD_DEFINITIONS(-DFLEA_PLTF_X86_64)
#SET(CSEC_INLC_DIR ../csec/include CACHE STRING "include directory of the csec framework")

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: 'Debug' and 'Release'."
      FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)

SET(mudflap "false" CACHE STRING "wether to compile in mudflap for gcc")
IF(${mudflap} STREQUAL "true")
	ADD_DEFINITIONS(-fmudflap )
	SET(MUDFLAP_LIB mudflap)
  SET(MUDFLAP_STR -mf)
ELSEIF(${mudflap} STREQUAL "false")
	
ELSE()
	MESSAGE(FATAL_ERROR "mudflap must be either 'true' or 'false'")
ENDIF()

IF(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "DEBUG" OR CMAKE_BUILD_TYPE STREQUAL "debug")
    ADD_DEFINITIONS(-g)
    SET(DEBUG_STRING _d)
ENDIF()


LINK_DIRECTORIES(${CMAKE_SOURCE_DIR}/Libraries/Botan-1.11.19/)

SET(BUILD_STATIC false CACHE STRING
      "Wether to build also a static version of the library or not: true/false"
      )
IF(BUILD_STATIC STREQUAL true)
    SET(DO_BUILD_STATIC 1)
ENDIF()

SET(BUILD_SHARED true CACHE STRING
      "Wether to build also a common (dynamic) version of the library or not: true/false"
      )
IF(BUILD_SHARED STREQUAL true)
    SET(DO_BUILD_SHARED 1)
ENDIF()

SET(VERSION_STRING ${SPECIAL_BUILD}${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}${CM_STRING}${DEBUG_STRING})
#SET(LIB_NAME_STRING flea)
SET(FULL_LIB_STRING ${LIB_NAME_STRING}-${VERSION_STRING}${MUDFLAP_STR})
SET(FULL_LIB_STRING_STATIC
  ${LIB_NAME_STRING}_static-${VERSION_STRING}${MUDFLAP_STR})

SET(PROJECT_BINARY_DIR build)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR})
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})


# Directories
SET(INCLUDE_DIR include ${CMAKE_SOURCE_DIR}/Libraries/Botan-1.11.19/build/include/ src )

SET(SRC_DIR src )



# List of source files
FILE(GLOB CertFuzzer_SRC ${SRC_DIR}/*.cpp)
#FILE(GLOB TEST_SRCS test/src/pc/*.cpp test/src/common/*.c)

# include folder with header files
INCLUDE_DIRECTORIES(${INCLUDE_DIR} )
#INCLUDE_DIRECTORIES(${CSEC_INLC_DIR})

IF(DO_BUILD_SHARED)
    #ADD_LIBRARY(${FULL_LIB_STRING} SHARED ${FLEA_SRCS})
    #TARGET_LINK_LIBRARIES(${FULL_LIB_STRING} ${MUDFLAP_LIB} m)
ENDIF()

IF(DO_BUILD_STATIC)
    #ADD_LIBRARY(${FULL_LIB_STRING_STATIC} STATIC ${FLEA_SRCS})
ENDIF()
#src/manipulator.cpp src/DERObject.cpp src/help.cpp
# ADD_EXECUTABLE(CertFuzzer src/main.cpp  ${CertFuzzer_SRC})
ADD_EXECUTABLE(CertFuzzer src/test.cpp  ${CertFuzzer_SRC})
# TARGET_LINK_LIBRARIES(CertFuzzer botan-1.11)
target_link_libraries(CertFuzzer ${CMAKE_SOURCE_DIR}/Libraries/Botan-1.11.19/libbotan-1.11.a)
target_link_libraries(CertFuzzer pthread)

ADD_LIBRARY(LibCertFuzzer STATIC ${CertFuzzer_SRC})
target_link_libraries(LibCertFuzzer -Wl,--whole-archive ${CMAKE_SOURCE_DIR}/Libraries/Botan-1.11.19/libbotan-1.11.a -Wl,--no-whole-archive)
target_link_libraries(LibCertFuzzer pthread)
