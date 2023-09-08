cmake_minimum_required(VERSION 3.12)

project(TEST)

aux_source_directory(../src/ SRC)

include_directories(../include)

include_directories(/usr/local/include/palisade)

include_directories(/usr/local/include/palisade/core)

add_compile_options( -std=c++11 -O2)

add_executable(main test.cpp ${SRC})

target_link_libraries(main  PALISADEcore)





