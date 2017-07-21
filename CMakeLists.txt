#---------------------------------------------------------------------------------
cmake_minimum_required(VERSION 2.8.0 FATAL_ERROR)
#---------------------------------------------------------------------------------

if (GTESTDIR)
  # set by parent project, leave it
else()
  set(GTESTDIR "${CMAKE_SOURCE_DIR}/deps/gtest")
endif()

#---------------------------------------------------------------------------------
# Setup the top most project
#---------------------------------------------------------------------------------
set(PROJECT_NAME "ZDNSParser")
message(STATUS "************  Starting ${PROJECT_NAME}  ************")
project(${PROJECT_NAME})

#---------------------------------------------------------------------------------
# Include house keeping cmake file to keep master file cleaner
#---------------------------------------------------------------------------------
include(cmake/env_setup.cmake)
include(cmake/cxx_flag_overrides.cmake)

# subdirs

add_subdirectory(src)
add_subdirectory(test)

