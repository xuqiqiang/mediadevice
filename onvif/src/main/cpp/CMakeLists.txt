# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

set(ijkffmpeg_DIR ${CMAKE_SOURCE_DIR}/ijkffmpeg)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
             sffstreamer

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             rtmp/Mybs.c rtmp/data.c rtmp/video.c rtmp/rtmp.c)

#增加so文件动态共享库，${ANDROID_ABI}表示so文件的ABI类型的路径
add_library(
             ijkffmpeg
             SHARED
             IMPORTED)
set_target_properties(
             ijkffmpeg
             PROPERTIES
             IMPORTED_LOCATION
             ${ijkffmpeg_DIR}/lib/${ANDROID_ABI}/libijkffmpeg.so)

#增加include包含的路径
target_include_directories(
             sffstreamer
             PRIVATE
             ${ijkffmpeg_DIR}/include)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       sffstreamer

                       # Links the target library to the log library
                       # included in the NDK.
                       ijkffmpeg
                       ${log-lib} )