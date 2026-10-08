add_executable(trapdoor-trace
  src/main.cpp
  src/seccomp.cpp
  src/mem.cpp
)

target_include_directories(trapdoor-trace PRIVATE src)

install(TARGETS trapdoor-trace RUNTIME DESTINATION bin)
