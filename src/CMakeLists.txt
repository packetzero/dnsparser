set (PROJECT_NAME zdnsparser)
message(STATUS "************  Starting ${PROJECT_NAME}  ************")
project(${PROJECT_NAME})



file(GLOB HDRS "*.h" "net/*.h" "include/*.h" "common/*.h" "${CMAKE_SYSTEM_NAME}/*.h")
file(GLOB SRCS "*.cpp" "net/*.cpp" "common/*.cpp" "dns/*.cpp" "${CMAKE_SYSTEM_NAME}/*.cpp")

add_library (${PROJECT_NAME} ${SRCS} ${HDRS})

