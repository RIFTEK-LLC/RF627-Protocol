cmake_minimum_required(VERSION 3.13)



###############################################################################
## 3RD-PARTY
## dependencies for the project
###############################################################################
project(3rdparty LANGUAGES C)



###############################################################################
## INCLUDING SUBDIRECTORIES
## Adding subdirectories according to the 3rd-party configuration
###############################################################################
#add_subdirectory(platform_methods)
add_subdirectory(custom_vector)
add_subdirectory(endian_conv)
add_subdirectory(custom_string)
