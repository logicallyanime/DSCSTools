# specify no SHARED/STATIC, so BUILD_SHARED_LIBS gets used
add_library(MVGLTools)

target_sources(MVGLTools
  PRIVATE
  SaveFile.cpp
  AFS2.cpp
  MDB1.cpp
  EXPA.cpp
  Compressors.cpp
)

target_include_directories(MVGLTools
  PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_features(MVGLTools PUBLIC cxx_std_23)
target_link_libraries(MVGLTools PUBLIC doboz lz4 AriaCsvParser Boost::property_tree Boost::multiprecision Boost::crc Boost::regex Boost::asio)
