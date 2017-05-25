#ifndef _COM_DFTC_ONVIF_PLATFORM_H_
#define _COM_DFTC_ONVIF_PLATFORM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _DEBUG_

#ifdef ANDROID
#include <jni.h>
#include <android/log.h>
#define LOGE(format, ...)  __android_log_print(ANDROID_LOG_ERROR, "(>_<)", format, ##__VA_ARGS__)
#define LOGI(format, ...)  __android_log_print(ANDROID_LOG_INFO,  "(^_^)", format, ##__VA_ARGS__)
#define printf(format, ...)  __android_log_print(ANDROID_LOG_INFO, "(^_^)", format, ##__VA_ARGS__)
#else
#define LOGE(format, ...)  printf("(>_<) " format "\n", ##__VA_ARGS__)
#define LOGI(format, ...)  printf("(^_^) " format "\n", ##__VA_ARGS__)
#endif

typedef int BOOL;
#define TRUE  1
#define FALSE 0

#endif
