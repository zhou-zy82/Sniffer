# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\sniffer_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\sniffer_autogen.dir\\ParseCache.txt"
  "sniffer_autogen"
  )
endif()
