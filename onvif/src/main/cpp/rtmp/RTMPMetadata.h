#ifndef __RTMPSTREAM_H
#define __RTMPSTREAM_H

#include "librtmp/rtmp_sys.h"
#include "librtmp/log.h"
#include "librtmp/amf.h"
#include <stdio.h>
#define RTMP_HEAD_SIZE   (sizeof(RTMPPacket)+RTMP_MAX_HEADER_SIZE)

typedef struct _RTMPMetadata
{
    // video, must be h264 type
    unsigned int nWidth;
    unsigned int nHeight;
    unsigned int nFrameRate; // fps
    unsigned int nVideoDataRate; // bps
    unsigned int nSpsLen;
    unsigned char Sps[1024];
    unsigned int nPpsLen;
    //unsigned char	Pps[1024];
    unsigned char Pps[2048];
    // audio, must be aac type
    bool bHasAudio;
    unsigned int nAudioSampleRate;
    unsigned int nAudioSampleSize;
    unsigned int nAudioChannels;
    char pAudioSpecCfg;
    unsigned int nAudioSpecCfgLen;

} RTMPMetadata, *LPRTMPMetadata;

#endif
