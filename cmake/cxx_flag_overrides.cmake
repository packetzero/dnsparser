#cxx_flag_overrides.cmake
if(MSVC)
	set(CMAKE_CXX_FLAGS_DEBUG "/D_DEBUG /D_CRT_SECURE_NO_WARNINGS /DCONFUSE_STATIC_LIB /DPCRE_STATIC /D_CONSOLE /DCURL_STATICLIB /DBRAND_$ENV{BRAND} /DWPCAP /DHAVE_REMOTE /MTd /Zi /Ob0 /Od /RTC1 /D_VARIADIC_MAX=10 " CACHE STRING "" FORCE)
	set(CMAKE_CXX_FLAGS_MINSIZEREL "/D_CRT_SECURE_NO_WARNINGS /DCONFUSE_STATIC_LIB /DPCRE_STATIC /D_CONSOLE /DCURL_STATICLIB /DWPCAP /DHAVE_REMOTE /MT /O1 /Ob1 /D NDEBUG" CACHE STRING "" FORCE)
	set(CMAKE_CXX_FLAGS_RELEASE "/D_CRT_SECURE_NO_WARNINGS /DCONFUSE_STATIC_LIB /DPCRE_STATIC /D_CONSOLE /DCURL_STATICLIB /DWPCAP /DHAVE_REMOTE /MT /O1 /Ob1 /D NDEBUG /D_VARIADIC_MAX=10 " CACHE STRING "" FORCE)
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/D_CRT_SECURE_NO_WARNINGS /DCONFUSE_STATIC_LIB /DPCRE_STATIC /D_CONSOLE /DCURL_STATICLIB /DWPCAP /DHAVE_REMOTE /MT /Zi /O2 /Ob1 /D NDEBUG" CACHE STRING "" FORCE)
endif()

IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	set(CMAKE_DL_LIBS "dl")
	set(CMAKE_CXX_FLAGS "-DWFMO=1  -I${GTESTDIR}/include")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

if(UNIX)
	#Compiler-specific c++11 activation
	#GCC_Version 4.7 and greater support c++11
	#GCC_Version 4.3 to 4.6 support c++0x
	#GCC_Version 4.7 Explicit Virtual Overrides (N2928)
	#GCC_Version 4.6 Null Pointer Constant (N2431)
	#GCC_Version 4.6 x86intrin.h support

  if($ENV{CXX})
    set(CMAKE_CXX_COMPILER $ENV{CXX} CACHE FILEPATH "CXX Compiler")
  endif()
  if($ENV{CC})
    set(CMAKE_CC_COMPILER $ENV{CC} CACHE FILEPATH "CC Compiler")
  endif()

	if ("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU")
                set(CMAKE_CXX_FLAGS "" CACHE STRING "" FORCE)
                set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} " )
		execute_process(COMMAND ${CMAKE_CXX_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
		if (GCC_VERSION VERSION_GREATER 4.7 OR GCC_VERSION VERSION_EQUAL 4.7)
			message(STATUS "************  Compiler has support for c++11, nullptr constant, virtual override and intrinsic header")
			set(EXTENSION_SUPPORT "-std=c++11")
			set(NULL_POINTER_CONSTANT "-DNULL_POINTER_CONSTANT")
			set(EXPLICIT_VIRTUAL_OVERRIDES "-DEXPLICIT_VIRTUAL_OVERRIDES")
			set(INTRINSIC_HEADER "-DINTRINSIC_HEADER")
                elseif (GCC_VERSION VERSION_GREATER 4.6 OR GCC_VERSION VERSION_EQUAL 4.6)
                        message(STATUS "************  Compiler has support for c++0x, nullptr constant and intrinsic header")
			set(EXTENSION_SUPPORT "-std=c++0x")
			set(NULL_POINTER_CONSTANT "-DNULL_POINTER_CONSTANT")
			set(INTRINSIC_HEADER "-DINTRINSIC_HEADER")
                elseif (GCC_VERSION VERSION_GREATER 4.3 OR GCC_VERSION VERSION_EQUAL 4.3)
			message(STATUS "************  Compiler has support for c++0x")
			set(EXTENSION_SUPPORT "-std=c++0x")
                else()
			message(STATUS "************  Compiler does not support c++11 or c++0x, null pointer constant, virtual overrides or intrinsic header")
                endif()
                set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTENSION_SUPPORT} -Wall -DHAVE_CONFIG_H -DCONFUSE_STATIC_LIB -DCURL_STATICLIB -DSQLITE_THREADSAFE=1 -DWFMO -DNO_SSL_DL -DCMAKE_BUILD" CACHE STRING "" FORCE)
	endif()

  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DBRAND_$ENV{BRAND} -I${GTESTDIR}/include" )

	message(STATUS "************  CXX Flags ${CMAKE_CXX_FLAGS}")
	if (${CMAKE_BUILD_TYPE} MATCHES "Debug")
	        set(CMAKE_CXX_FLAGS_DEBUG "-MD -MP -MF -O0 -g -DDEBUG -D_DEBUG")
        	message(STATUS "************  CXX Debug Flags ${CMAKE_CXX_FLAGS_DEBUG}")
	else()
	        set(CMAKE_CXX_FLAGS_RELEASE "-MD -MP -MF -Os -g")
        	message(STATUS "************  CXX Release Flags${CMAKE_CXX_FLAGS_RELEASE}")
	endif()

    add_definitions(${NULL_POINTER_CONSTANT} ${INTRISIC_HEADER})

    set(CMAKE_EXE_LINKER_FLAGS "-l${CMAKE_DL_LIBS}" CACHE STRING "" FORCE)
    set(CMAKE_MODULE_LINKER_FLAGS "-l${CMAKE_DL_LIBS}" CACHE STRING "" FORCE)

endif()
