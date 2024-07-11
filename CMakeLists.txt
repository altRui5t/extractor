cmake_minimum_required(VERSION 3.16.3)

project(extractor)

include(FindPCAP.cmake)
set(SRC src/main.cpp src/capReader.cpp src/capReader.h)

add_executable (extractor ${SRC}  )
target_link_libraries(extractor ${PCAP_LIBRARY})