cmake_minimum_required(VERSION 3.13)

project(LLVMAnalysisPass)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION}")

add_library(LLVMAnalysisPass SHARED
    SecuritySensitivityPass.cpp
    WriteAnalysis.cpp
    SecurityState.cpp   
)

target_include_directories(LLVMAnalysisPass PRIVATE ${LLVM_INCLUDE_DIRS})

target_compile_definitions(LLVMAnalysisPass PRIVATE ${LLVM_DEFINITIONS})

set_target_properties(LLVMAnalysisPass PROPERTIES
    COMPILE_FLAGS "-fno-rtti"
)