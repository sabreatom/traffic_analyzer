cmake_minimum_required(VERSION 3.5.1)
project (packet_sniffer)
add_executable(packet_sniffer packet_sniffer.c)

include_directories(/usr/include)
link_directories(/usr/lib)
target_link_libraries(packet_sniffer sqlite3)