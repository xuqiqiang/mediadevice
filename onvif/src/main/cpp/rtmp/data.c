#include "data.h"

AVFormatNode *AllocAVFormat()
{
    AVFormatNode *pAVFormat = (AVFormatNode*) malloc(sizeof(AVFormatNode));
    if (!pAVFormat)
    {
        LOGE("Alloc AVFormat error!");
        return NULL;
    }
    pAVFormat->pFormatCtx = NULL;
    pAVFormat->pNext = NULL;
    return pAVFormat;
}

BOOL InitAVFormatQueue(AVFormatQueue **q)
{
    AVFormatQueue *queue = (AVFormatQueue*) malloc(sizeof(AVFormatQueue));
    if (!queue)
    {
        LOGE("Alloc AVFormatQueue error!");
        return FALSE;
    }
    queue->head = AllocAVFormat();
    if (!queue->head)
        return FALSE;
    queue->tail = queue->head;
    *q = queue;
    return TRUE;
}

BOOL IsAVFormatQueueEmpty(AVFormatQueue *q)
{
    return (q->head->pNext == NULL);
}

BOOL PushAVFormat(AVFormatQueue *q, AVFormatNode *a)
{
    q->tail->pNext = a;
    q->tail = a;
    return TRUE;
}

BOOL PopAVFormat(AVFormatQueue *q, AVFormatNode **a)
{
    if (IsAVFormatQueueEmpty(q))
    {
        LOGE("AVFormatQueue empty!");
        return FALSE;
    }
    *a = q->head->pNext;
    q->head->pNext = (*a)->pNext;
    if (q->tail == *a)
    {
        LOGI("AVFormatQueue empty!");
        q->tail = q->head;
    }
    return TRUE;
}

BOOL PopAVFormatById(AVFormatQueue *q, AVFormatNode **a, int id)
{
    if (IsAVFormatQueueEmpty(q))
    {
        LOGE("AVFormatQueue empty!");
        return FALSE;
    }

    AVFormatNode *p = q->head;
    while (p->pNext != NULL && p->pNext->id != id)
        p = p->pNext;

    if (p->pNext == NULL)
    {
        LOGE("AVFormatNode not find! id:%d", id);
        return FALSE;
    }
    *a = p->pNext;
    p->pNext = (*a)->pNext;
    if (q->tail == *a)
    {
        LOGI("AVFormatQueue empty!");
        q->tail = q->head;
    }
    return TRUE;
}

BOOL GetAVFormatById(AVFormatQueue *q, AVFormatNode **a, int id)
{
    if (IsAVFormatQueueEmpty(q))
    {
        LOGE("AVFormatQueue empty!");
        return FALSE;
    }

    AVFormatNode *p = q->head->pNext;
    while (p != NULL && p->id != id)
        p = p->pNext;

    if (p == NULL)
    {
        LOGE("AVFormatNode not find! id:%d", id);
        return FALSE;
    }

    *a = p;
    return TRUE;
}

BOOL FreeAVFormat(AVFormatNode *pAVFormat)
{
    if (pAVFormat)
    {
        if (pAVFormat->pFormatCtx)
        {
            avformat_close_input(&pAVFormat->pFormatCtx);
            pAVFormat->pFormatCtx = NULL;
        }
        free(pAVFormat);
    }
    return TRUE;
}

///////////////////

RtmpNode *AllocRtmpNode()
{
    RtmpNode *pRtmpNode = (RtmpNode *) malloc(sizeof(RtmpNode));
    if (!pRtmpNode)
    {
        LOGE("Alloc RtmpNode error!");
        return NULL;
    }
    pRtmpNode->m_pRtmp = NULL;
    pRtmpNode->m_SendSpsPps = FALSE;
    pRtmpNode->pNext = NULL;
    return pRtmpNode;
}

BOOL InitRtmpNodeQueue(RtmpNodeQueue **q)
{
    RtmpNodeQueue *queue = (RtmpNodeQueue*) malloc(sizeof(RtmpNodeQueue));
    if (!queue)
    {
        LOGE("Alloc RtmpNodeQueue error!");
        return FALSE;
    }
    queue->head = AllocRtmpNode();
    if (!queue->head)
        return FALSE;
    queue->tail = queue->head;
    *q = queue;
    return TRUE;
}

BOOL IsRtmpNodeQueueEmpty(RtmpNodeQueue *q)
{
    return (q->head->pNext == NULL);
}

BOOL PushRtmpNode(RtmpNodeQueue *q, RtmpNode *a)
{
    q->tail->pNext = a;
    q->tail = a;
    return TRUE;
}

BOOL PopRtmpNode(RtmpNodeQueue *q, RtmpNode **a)
{
    if (IsRtmpNodeQueueEmpty(q))
    {
        LOGE("RtmpNodeQueue empty!");
        return FALSE;
    }
    *a = q->head->pNext;
    q->head = (*a)->pNext;
    if (q->tail == *a)
    {
        LOGI("RtmpNodeQueue empty!");
        q->tail = q->head;
    }
    return TRUE;
}

BOOL PopRtmpNodeById(RtmpNodeQueue *q, RtmpNode **a, int id)
{
    if (IsRtmpNodeQueueEmpty(q))
    {
        LOGE("RtmpNodeQueue empty!");
        return FALSE;
    }

    RtmpNode *p = q->head;
    while (p->pNext != NULL && p->pNext->id != id)
        p = p->pNext;

    if (p->pNext == NULL)
    {
        LOGE("RtmpNode not find! id:%d", id);
        return FALSE;
    }

    *a = p->pNext;
    p->pNext = (*a)->pNext;
    if (q->tail == *a)
    {
        LOGI("RtmpNodeQueue empty!");
        q->tail = q->head;
    }
    return TRUE;
}

BOOL GetRtmpNodeById(RtmpNodeQueue *q, RtmpNode **a, int id)
{
    if (IsRtmpNodeQueueEmpty(q))
    {
        LOGE("RtmpNodeQueue empty!");
        return FALSE;
    }

    RtmpNode *p = q->head->pNext;
    while (p != NULL && p->id != id)
        p = p->pNext;

    if (p == NULL)
    {
        LOGE("RtmpNode not find! id:%d", id);
        return FALSE;
    }

    *a = p;
    return TRUE;
}

BOOL FreeRtmpNode(RtmpNode *pRtmpNode)
{
    if (pRtmpNode)
    {
        if (pRtmpNode->m_pRtmp)
        {
            RTMP_Close(pRtmpNode->m_pRtmp);
            RTMP_Free(pRtmpNode->m_pRtmp);
            pRtmpNode->m_pRtmp = NULL;
        }
        free(pRtmpNode);
    }
    return TRUE;
}
