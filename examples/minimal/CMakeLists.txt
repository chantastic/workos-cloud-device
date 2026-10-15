cmake_minimum_required(VERSION 3.22)
# Pick up components/workos_cloud from this repo. In your own project, point
# EXTRA_COMPONENT_DIRS at <path to workos-cloud-device>/components instead.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(workos_cloud_minimal)
