# Add source to this project's executable.
add_executable(DSTSToolsCLI)

target_sources(DSTSToolsCLI PRIVATE DSTSTools.cpp)
target_compile_features(DSTSToolsCLI PUBLIC cxx_std_23)
target_link_libraries(DSTSToolsCLI PRIVATE DSCSTools Boost::program_options)

# Install
install(TARGETS DSTSToolsCLI RUNTIME DESTINATION .)
install(DIRECTORY ../structures/ DESTINATION structures/)
install(FILES ../README.md ../LICENSE ../THIRD-PARTY-NOTICE DESTINATION .)

set(CPACK_GENERATOR "ZIP")
include(CPack)
