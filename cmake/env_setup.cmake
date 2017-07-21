#---------------------------------------------------------------------------------
# CMake on Linux does not set the default build type so we default to Debug
#---------------------------------------------------------------------------------
if (UNIX)
	if (NOT CMAKE_BUILD_TYPE)
		set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
	endif()
	set(PTHREAD_LIB pthread)

endif(UNIX)

#---------------------------------------------------------------------------------
# Set Global Link Directories
#---------------------------------------------------------------------------------
link_directories(${LIBRARY_OUTPUT_PATH})

#---------------------------------------------------------------------------------
# Third Party IPWorks networking import libs necessary for Windows.  For Linux
# the libraries are compiled from a master supplied cpp file and linked right in.
#---------------------------------------------------------------------------------
if (WIN32)
	set (PCAP_LIB "${PROJECT_SOURCE_DIR}/deps/winpcap/lib/wpcap.lib")

	set (OS_LIBS ws2_32.lib rpcrt4.lib Crypt32.lib Wldap32.lib Shlwapi.lib Wbemuuid.lib version.lib psapi.lib Wtsapi32.lib Secur32.lib )
endif(WIN32)

if (UNIX)
	set(OS_LIBS pthread dl rt m c z pcap)
endif(UNIX)

IF(APPLE)
	set(LIBS "/usr/local/lib")
	set(OS_LIBS pthread dl m c z -lpcap)
	set(ZFLOW_LDFLAGS "-L${LIBS}")
	set(CMAKE_EXE_LINKER_FLAGS "${ZFLOW_LDFLAGS}")
ENDIF(APPLE)

#---------------------------------------------------------------------------------
# Set Global Include Directories
#---------------------------------------------------------------------------------
if (WIN32)
include_directories(.
	${PROJECT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${PROJECT_SOURCE_DIR}/deps/winpcap/include
	${PROJECT_SOURCE_DIR}/deps/gtest/include
)
endif(WIN32)

if (UNIX)
include_directories(.
        ${PROJECT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}
        /usr/local/include
)
endif(UNIX)

#---------------------------------------------------------------------------------
# Set Binary Output Directories
#---------------------------------------------------------------------------------
# These correspond to the "Where to build the binaries" text entry box in cmake-gui
#---------------------------------------------------------------------------------
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)	#.dll, .so
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

#allow user control over verbose makefile output
if (VerboseOutput)
	set(CMAKE_VERBOSE_MAKEFILE true)
endif()
