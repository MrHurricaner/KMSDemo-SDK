# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
        MpcNative

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        src/main/cpp/com_juzix_kms_NativeECDSA.c
        src/main/cpp/bn.c
        src/main/cpp/bn_test.c
        src/main/cpp/cela_rand.c
        src/main/cpp/common.c
        src/main/cpp/ecdsa.c
        src/main/cpp/common.c
        src/main/cpp/ecdsa_di_co.c
        src/main/cpp/ecdsa_di_co_test.c
        src/main/cpp/ecdsa_test.c
        src/main/cpp/ecschnorr.c
        src/main/cpp/pailler.c
        src/main/cpp/pailler_test.c
        src/main/cpp/secp256k1_curve.c
        src/main/cpp/secp256k1_fp_ecp.c
        src/main/cpp/secp256k1_fp_ecp_test.c
        src/main/cpp/sha2.cpp
        src/main/cpp/u8operation.c)

include_directories(src/main/cpp)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
        MpcNative

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib})