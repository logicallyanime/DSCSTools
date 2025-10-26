cmake_minimum_required(VERSION 3.28)

add_library(doboz STATIC Common.h Compressor.cpp Compressor.h Decompressor.cpp Decompressor.h Dictionary.cpp Dictionary.h)
set_property(TARGET doboz PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(doboz
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
