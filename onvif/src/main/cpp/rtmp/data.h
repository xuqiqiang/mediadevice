#ifndef __DATA_H
#define __DATA_H

#include "platform.h"
#include "libavformat/avformat.h"
#include "librtmp/rtmp.h"

typedef struct AVFormat
{
    int id;
    int videoindex;
    AVFormatContext *pFormatCtx;
    struct AVFormat *pNext;
} AVFormatNode;

typedef struct
{
    AVFormatNode *head;
    AVFormatNode *tail;
} AVFormatQueue;

AVFormatNode *AllocAVFormat();

BOOL InitAVFormatQueue(AVFormatQueue **q);

BOOL IsAVFormatQueueEmpty(AVFormatQueue *q);

BOOL PushAVFormat(AVFormatQueue *q, AVFormatNode *a);

BOOL PopAVFormat(AVFormatQueue *q, AVFormatNode **a);

BOOL PopAVFormatById(AVFormatQueue *q, AVFormatNode **a, int id);

BOOL GetAVFormatById(AVFormatQueue *q, AVFormatNode **a, int id);

BOOL FreeAVFormat(AVFormatNode *pAVFormat);

typedef struct Rtmp
{
    int id;
    BOOL m_SendSpsPps;
    RTMP *m_pRtmp;
    int width;
    int height;
    int rate;
    struct Rtmp *pNext;
} RtmpNode;

typedef struct
{
    RtmpNode *head;
    RtmpNode *tail;
} RtmpNodeQueue;

RtmpNode *AllocRtmpNode();

BOOL InitRtmpNodeQueue(RtmpNodeQueue **q);

BOOL IsRtmpNodeQueueEmpty(RtmpNodeQueue *q);

BOOL PushRtmpNode(RtmpNodeQueue *q, RtmpNode *a);

BOOL PopRtmpNode(RtmpNodeQueue *q, RtmpNode **a);

BOOL PopRtmpNodeById(RtmpNodeQueue *q, RtmpNode **a, int id);

BOOL GetRtmpNodeById(RtmpNodeQueue *q, RtmpNode **a, int id);

BOOL FreeRtmpNode(RtmpNode *pRtmpNode);

#endif
