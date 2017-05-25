#! /usr/bin/env bash
#
# Copyright (C) 2014 Miguel Botón <waninkoko@gmail.com>
# Copyright (C) 2014 Zhang Rui <bbcallen@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#--------------------
set -e

if [ -z "$ANDROID_NDK" ]; then
    echo "You must define ANDROID_NDK before starting."
    echo "They must point to your NDK directories.\n"
    exit 1
fi

#--------------------
# common defines
FF_ARCH=$1
if [ -z "$FF_ARCH" ]; then
    echo "You must specific an architecture 'arm, armv7a, x86, ...'.\n"
    exit 1
fi


FF_BUILD_ROOT=`pwd`
FF_ANDROID_PLATFORM=android-9


FF_BUILD_NAME=
FF_SOURCE=
FF_CROSS_PREFIX=

FF_CFG_FLAGS=
FF_PLATFORM_CFG_FLAGS=

FF_EXTRA_CFLAGS=
FF_EXTRA_LDFLAGS=



#--------------------
echo ""
echo "--------------------"
echo "[*] make NDK standalone toolchain"
echo "--------------------"
. ./tools/do-detect-env.sh
FF_MAKE_TOOLCHAIN_FLAGS=$IJK_MAKE_TOOLCHAIN_FLAGS
FF_MAKE_FLAGS=$IJK_MAKE_FLAG
FF_GCC_VER=$IJK_GCC_VER
FF_GCC_64_VER=$IJK_GCC_64_VER


#----- armv7a begin -----
if [ "$FF_ARCH" = "armv7a" ]; then
    FF_BUILD_NAME=rtmpdump-armv7a
    FF_SOURCE=$FF_BUILD_ROOT/$FF_BUILD_NAME

    FF_BUILD_NAME_POLARSSL=polarssl-armv7a
    FF_BUILD_NAME_OPENSSL=openssl-armv7a
	
    FF_CROSS_PREFIX=toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/arm-linux-androideabi

elif [ "$FF_ARCH" = "armv5" ]; then
    FF_BUILD_NAME=rtmpdump-armv5
    FF_SOURCE=$FF_BUILD_ROOT/$FF_BUILD_NAME

    FF_BUILD_NAME_POLARSSL=polarssl-armv7a
    FF_BUILD_NAME_OPENSSL=openssl-armv5
	
    FF_CROSS_PREFIX=toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/arm-linux-androideabi

elif [ "$FF_ARCH" = "x86" ]; then
    FF_BUILD_NAME=rtmpdump-x86
    FF_SOURCE=$FF_BUILD_ROOT/$FF_BUILD_NAME

    FF_BUILD_NAME_POLARSSL=polarssl-x86
    FF_BUILD_NAME_OPENSSL=openssl-x86
	
    FF_CROSS_PREFIX=toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/i686-linux-android

elif [ "$FF_ARCH" = "x86_64" ]; then
    FF_ANDROID_PLATFORM=android-21

    FF_BUILD_NAME=rtmpdump-x86_64
    FF_SOURCE=$FF_BUILD_ROOT/$FF_BUILD_NAME

    FF_BUILD_NAME_POLARSSL=polarssl-x86_64
    FF_BUILD_NAME_OPENSSL=openssl-x86_64

    FF_CROSS_PREFIX=toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/x86_64-linux-android

elif [ "$FF_ARCH" = "arm64" ]; then
    FF_ANDROID_PLATFORM=android-21

    FF_BUILD_NAME=rtmpdump-arm64
    FF_SOURCE=$FF_BUILD_ROOT/$FF_BUILD_NAME

    FF_BUILD_NAME_POLARSSL=polarssl-arm64
    FF_BUILD_NAME_OPENSSL=openssl-arm64

    FF_CROSS_PREFIX=toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android

else
    echo "unknown architecture $FF_ARCH";
    exit 1
fi

FF_PREFIX=$FF_BUILD_ROOT/build/$FF_BUILD_NAME/output

mkdir -p $FF_PREFIX

echo ""
echo "--------------------"
echo "[*] check rtmpdump env"
echo "--------------------"
export COMMON_FF_CFG_FLAGS=

FF_CFG_FLAGS="$FF_CFG_FLAGS $COMMON_FF_CFG_FLAGS"

#--------------------
# Standard options:


#FF_CFG_FLAGS="$FF_CFG_FLAGS no-asm"
#FF_CFG_FLAGS="$FF_CFG_FLAGS --prefix=$FF_PREFIX"

CC="${ANDROID_NDK}/${FF_CROSS_PREFIX}-gcc --sysroot=${ANDROID_NDK}/platforms/android-8/arch-arm"
#AR="${ANDROID_NDK}/${FF_CROSS_PREFIX}-ar"
#RANLIB="${ANDROID_NDK}/${FF_CROSS_PREFIX}-ranlib"

SYS=android

FF_DEP_POLARSSL_INC=$FF_BUILD_ROOT/build/$FF_BUILD_NAME_POLARSSL/output/include
FF_DEP_POLARSSL_LIB=$FF_BUILD_ROOT/build/$FF_BUILD_NAME_POLARSSL/output/lib

FF_DEP_OPENSSL_INC=$FF_BUILD_ROOT/build/$FF_BUILD_NAME_OPENSSL/output/include
FF_DEP_OPENSSL_LIB=$FF_BUILD_ROOT/build/$FF_BUILD_NAME_OPENSSL/output/lib

#--------------------
# with polarssl
echo ""
echo "--------------------"
echo "[*] check polarssl env"
echo "--------------------"
if [ -f "${FF_DEP_POLARSSL_LIB}/libpolarssl.a" ]; then
    echo "polarssl detected"
else
    echo "You should compile polarssl before";
    exit 1
fi

#--------------------
# with openssl
echo ""
echo "--------------------"
echo "[*] check openssl env"
echo "--------------------"
if [ -f "${FF_DEP_OPENSSL_LIB}/libssl.a" ]; then
    echo "openssl detected"
else
    echo "You should compile openssl before";
    exit 1
fi

#--------------------
echo ""
echo "--------------------"
echo "[*] configurate rtmpdump"
echo "--------------------"
cd $FF_SOURCE

#--------------------
echo ""
echo "--------------------"
echo "[*] compile rtmpdump"
echo "--------------------"
make CC="$CC" SYS=$SYS \
CROSS_COMPILE="${ANDROID_NDK}/${FF_CROSS_PREFIX}-" \
INC="-I${FF_DEP_POLARSSL_INC}" \
LDFLAGS="-L${FF_DEP_POLARSSL_LIB} -shared" \
LIBS="-lpolarssl" \
CRYPTO=POLARSSL
#make $FF_MAKE_FLAGS
make install CC="$CC" \
INC="-I${FF_DEP_OPENSSL_INC}" \
LDFLAGS="-L${FF_DEP_OPENSSL_LIB} -shared" \
DESTDIR=$FF_PREFIX

#--------------------
# remove shared library
#cd $FF_PREFIX/usr/local/lib
FF_PREFIX_LIB="$FF_PREFIX/usr/local/lib"
FF_PREFIX_SO_BACKUP="$FF_PREFIX_LIB/so_backup"
mkdir -p $FF_PREFIX_SO_BACKUP
mv -f $FF_PREFIX_LIB/*.so.1 $FF_PREFIX_SO_BACKUP
mv -f $FF_PREFIX_LIB/*.so $FF_PREFIX_SO_BACKUP

#--------------------
# copy objs
FF_PREFIX_OBJS="$FF_PREFIX/usr/local/objs"
mkdir -p $FF_PREFIX_OBJS
#cp -fp $FF_SOURCE/*.o $FF_PREFIX_OBJS
cp -fp $FF_SOURCE/librtmp/*.o $FF_PREFIX_OBJS

#--------------------
echo ""
echo "--------------------"
echo "[*] link rtmpdump"
echo "--------------------"
