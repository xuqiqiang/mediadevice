#include <stdio.h>
#include <time.h>
#include <pthread.h>

#include <libavutil/time.h>
#include "librtmp/rtmp_sys.h"
#include "librtmp/log.h"
#include "librtmp/amf.h"
#include "librtmp/rtmp.h"

#include <stdlib.h>
#include <stdbool.h>
#include <math.h>

#include "platform.h"

#include <signal.h>		// to catch Ctrl-C
#include <getopt.h>
#include <string.h>

#include "RTMPMetadata.h"

#include "data.h"

#include "video.h"

int FLV_CODECID_H264 = 7;

BOOL m_FFmpeg_Inited = FALSE;

AVFormatQueue *m_AVFormatQueue = NULL;

RtmpNodeQueue *m_RtmpNodeQueue = NULL;

int m_SerIdIndex = 0;

//Output FFmpeg's av_log()
void custom_log(void *ptr, int level, const char* fmt, va_list vl)
{

    //To TXT file
    FILE *fp = fopen("/storage/emulated/0/av_log.txt", "a+");
    if (fp)
    {
        vfprintf(fp, fmt, vl);
        fflush(fp);
        fclose(fp);
    }

    //To Logcat
    //LOGE(fmt, vl);
}

char * put_byte(char *output, uint8_t nVal)
{
    output[0] = nVal;
    return output + 1;
}
char * put_be16(char *output, uint16_t nVal)
{
    output[1] = nVal & 0xff;
    output[0] = nVal >> 8;
    return output + 2;
}
char * put_be24(char *output, uint32_t nVal)
{
    output[2] = nVal & 0xff;
    output[1] = nVal >> 8;
    output[0] = nVal >> 16;
    return output + 3;
}
char * put_be32(char *output, uint32_t nVal)
{
    output[3] = nVal & 0xff;
    output[2] = nVal >> 8;
    output[1] = nVal >> 16;
    output[0] = nVal >> 24;
    return output + 4;
}
char * put_be64(char *output, uint64_t nVal)
{
    output = put_be32(output, nVal >> 32);
    output = put_be32(output, nVal);
    return output;
}
char * put_amf_string(char *c, const char *str)
{
    uint16_t len = strlen(str);
    c = put_be16(c, len);
    memcpy(c, str, len);
    return c + len;
}
char * put_amf_double(char *c, double d)
{
    *c++ = AMF_NUMBER; /* type: Number */
    {
        unsigned char *ci, *co;
        ci = (unsigned char *) &d;
        co = (unsigned char *) c;
        co[0] = ci[7];
        co[1] = ci[6];
        co[2] = ci[5];
        co[3] = ci[4];
        co[4] = ci[3];
        co[5] = ci[2];
        co[6] = ci[1];
        co[7] = ci[0];
    }
    return c + 8;
}

BOOL SendPacket(RTMP *pRtmp, unsigned int nPacketType, unsigned char *data,
                unsigned int size, unsigned int nTimestamp)
{
    if (pRtmp == NULL)
    {
        LOGE("SendPacket pRtmp == NULL!\n");
        return FALSE;
    }

    RTMPPacket *packet = (RTMPPacket*) malloc(sizeof(RTMPPacket));// + size + 1);
    RTMPPacket_Alloc(packet, size + 1); //1024*64);//
    RTMPPacket_Reset(packet);

    packet->m_hasAbsTimestamp = 1;

    packet->m_packetType = nPacketType;
    packet->m_nChannel = 0x04;
    packet->m_headerType = RTMP_PACKET_SIZE_LARGE;
    packet->m_nTimeStamp = nTimestamp;
    packet->m_nInfoField2 = pRtmp->m_stream_id;
    packet->m_nBodySize = size;
    memcpy(packet->m_body, data, size);

    if (!RTMP_IsConnected(pRtmp))
    {
        LOGE( "RTMP_IsConnected error!\n");
    }

#ifdef _DEBUG_
    printf("SendPacket, size:%d, data:%s\n", size, data);
#endif
    int nRet = RTMP_SendPacket(pRtmp, packet, 0);
#ifdef _DEBUG_
    printf("SendPacket finish!\n");
#endif
    RTMPPacket_Free(packet);
    free(packet);
    if (!nRet)
    {
        LOGE( "RTMP_SendPacket error \n");
        return FALSE;
    }
    return nRet;
}

int SendMetadata(RTMP *pRtmp, LPRTMPMetadata lpMetaData)
{
    if (lpMetaData == NULL)
    {
        LOGE("SendMetadata lpMetaData == NULL!\n");
        return FALSE;
    }
    char body[1024] = { 0 };

    char * p = (char *) body;
    p = put_byte(p, AMF_STRING);
    p = put_amf_string(p, "@setDataFrame");

    p = put_byte(p, AMF_STRING);
    p = put_amf_string(p, "onMetaData");

    p = put_byte(p, AMF_OBJECT);
    p = put_amf_string(p, "copyright");
    p = put_byte(p, AMF_STRING);
    p = put_amf_string(p, "firehood");

    p = put_amf_string(p, "width");
    p = put_amf_double(p, lpMetaData->nWidth);

    p = put_amf_string(p, "height");
    p = put_amf_double(p, lpMetaData->nHeight);

    p = put_amf_string(p, "framerate");
    p = put_amf_double(p, lpMetaData->nFrameRate);

    p = put_amf_string(p, "videocodecid");
    p = put_amf_double(p, FLV_CODECID_H264);

    p = put_amf_string(p, "");
    p = put_byte(p, AMF_OBJECT_END);

    printf("SendMetadata 1  \n");
    SendPacket(pRtmp, RTMP_PACKET_TYPE_INFO, (unsigned char*) body, p - body,
               0);

    int i = 0;
    body[i++] = 0x17; // 1:keyframe  7:AVC
    body[i++] = 0x00; // AVC sequence header

    body[i++] = 0x00;
    body[i++] = 0x00;
    body[i++] = 0x00; // fill in 0;

    // AVCDecoderConfigurationRecord.
    body[i++] = 0x01; // configurationVersion
    body[i++] = lpMetaData->Sps[1]; // AVCProfileIndication
    body[i++] = lpMetaData->Sps[2]; // profile_compatibility
    body[i++] = lpMetaData->Sps[3]; // AVCLevelIndication
    body[i++] = 0xff; // lengthSizeMinusOne

    // sps nums
    body[i++] = 0xE1; //&0x1f
    // sps data length
    body[i++] = lpMetaData->nSpsLen >> 8;
    body[i++] = lpMetaData->nSpsLen & 0xff;
    // sps data
    memcpy(&body[i], lpMetaData->Sps, lpMetaData->nSpsLen);
    i = i + lpMetaData->nSpsLen;

    // pps nums
    body[i++] = 0x01; //&0x1f
    // pps data length
    body[i++] = lpMetaData->nPpsLen >> 8;
    body[i++] = lpMetaData->nPpsLen & 0xff;
    // sps data
    memcpy(&body[i], lpMetaData->Pps, lpMetaData->nPpsLen);
    i = i + lpMetaData->nPpsLen;
    printf("SendMetadata 2  \n");
    return SendPacket(pRtmp, RTMP_PACKET_TYPE_VIDEO, (unsigned char*) body, i,
                      0);

}

BOOL SendH264Packet(RTMP *pRtmp, unsigned char *data, unsigned int size,
                    BOOL bIsKeyFrame, unsigned int nTimeStamp)
{
    if (data == NULL && size < 11)
    {
        LOGE("SendH264Packet data error!\n");
        return FALSE;
    }

    unsigned char *body = (unsigned char *) malloc(size + 9);

    int i = 0;
    if (bIsKeyFrame)
    {
        body[i++] = 0x17; // 1:Iframe  7:AVC
    }
    else
    {
        body[i++] = 0x27; // 2:Pframe  7:AVC
    }
    body[i++] = 0x01; // AVC NALU
    body[i++] = 0x00;
    body[i++] = 0x00;
    body[i++] = 0x00;

    // NALU size
    body[i++] = size >> 24;
    body[i++] = size >> 16;
    body[i++] = size >> 8;
    body[i++] = size & 0xff;

    // NALU data
    memcpy(&body[i], data, size);

    BOOL bRet = SendPacket(pRtmp, RTMP_PACKET_TYPE_VIDEO, body, i + size,
                           nTimeStamp);

    free(body);

    return bRet;
}

BOOL m_read_frame;
int m_read_frame_time_out = 0;

static int interrupt_cb(void *ctx)
{
    if (m_read_frame)
    {
        //LOGI("interrupt_cb : %d",m_read_frame_time_out);
        m_read_frame_time_out++;
        if (m_read_frame_time_out > 3000)
        {
            LOGE("read_frame_time_out");
            m_read_frame_time_out = 0;
            return 1;
        }
    }
    return 0;
}

int push(char* input_str, char* output_str)
{
    AVOutputFormat *ofmt = NULL;
    AVFormatContext *ifmt_ctx = NULL, *ofmt_ctx = NULL;
    AVPacket pkt;

    int ret, i;

    //FFmpeg av_log() callback
    av_log_set_callback(custom_log);

    av_register_all();
    //Network
    avformat_network_init();
    //Input
    if ((ret = avformat_open_input(&ifmt_ctx, input_str, 0, 0)) < 0)
    {
        printf( "Could not open input file.");
        goto end;
    }
    LOGI( "avformat_find_stream_info");
    if ((ret = avformat_find_stream_info(ifmt_ctx, 0)) < 0)
    {
        printf( "error to retrieve input stream information");
        goto end;
    }

    //Output
    avformat_alloc_output_context2(&ofmt_ctx, NULL, "flv",output_str); //RTMP
    //avformat_alloc_output_context2(&ofmt_ctx, NULL, "mpegts", output_str);//UDP
    if (!ofmt_ctx)
    {
        printf( "Could not create output context\n");
        ret = AVERROR_UNKNOWN;
        goto end;
    }
    ofmt = ofmt_ctx->oformat;
    int videoindex = -1;
    for(i = 0; i<ifmt_ctx->nb_streams; i++)
        if(ifmt_ctx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO)
        {
            videoindex = i;
            break;
        }
    //Create output AVStream according to input AVStream
    AVStream *in_stream = ifmt_ctx->streams[videoindex];
    AVStream *out_stream = avformat_new_stream(ofmt_ctx, in_stream->codec->codec);
    if (!out_stream)
    {
        printf( "Error occurred when allocating output stream\n");
        ret = AVERROR_UNKNOWN;
        goto end;
    }
    //Copy the settings of AVCodecContext
    ret = avcodec_copy_context(out_stream->codec, in_stream->codec);
    if (ret < 0)
    {
        printf( "error to copy context from input to output stream codec context\n");
        goto end;
    }
    out_stream->codec->codec_tag = 0;
    if (ofmt_ctx->oformat->flags & AVFMT_GLOBALHEADER)
        out_stream->codec->flags |=  CODEC_FLAG_GLOBAL_HEADER;

    //Open output URL
    if (!(ofmt->flags & AVFMT_NOFILE))
    {
        ret = avio_open(&ofmt_ctx->pb, output_str, AVIO_FLAG_WRITE);
        if (ret < 0)
        {
            printf( "Could not open output URL '%s'", output_str);
            goto end;
        }
    }
    //Write file header
    ret = avformat_write_header(ofmt_ctx, NULL);
    if (ret < 0)
    {
        printf( "Error occurred when opening output URL : %d\n", ret);
        goto end;
    }

    int frame_index = 0;

    int64_t start_time = av_gettime();
    while (1)
    {
        AVStream *in_stream, *out_stream;
        //Get an AVPacket
        ret = av_read_frame(ifmt_ctx, &pkt);
        if (ret < 0)
            break;
        if(pkt.stream_index != videoindex)
        {
            av_free_packet(&pkt);
            continue;
        }
        //FIX：No PTS (Example: Raw H.264)
        //Simple Write PTS
        if(pkt.pts == AV_NOPTS_VALUE)
        {
            //Write PTS
            AVRational time_base1 = ifmt_ctx->streams[videoindex]->time_base;
            //Duration between 2 frames (us)
            int64_t calc_duration = (double)AV_TIME_BASE/av_q2d(ifmt_ctx->streams[videoindex]->r_frame_rate);
            //Parameters
            pkt.pts = (double)(frame_index*calc_duration)/(double)(av_q2d(time_base1)*AV_TIME_BASE);
            pkt.dts = pkt.pts;
            pkt.duration = (double)calc_duration/(double)(av_q2d(time_base1)*AV_TIME_BASE);
        }
        //Important:Delay
        if(pkt.stream_index == videoindex)
        {
            AVRational time_base = ifmt_ctx->streams[videoindex]->time_base;
            AVRational time_base_q =  {1,AV_TIME_BASE};
            int64_t pts_time = av_rescale_q(pkt.dts, time_base, time_base_q);
            int64_t now_time = av_gettime() - start_time;
            if (pts_time > now_time)
                av_usleep(pts_time - now_time);
        }

        in_stream  = ifmt_ctx->streams[pkt.stream_index];
        out_stream = ofmt_ctx->streams[pkt.stream_index];
        /* copy packet */
        //Convert PTS/DTS
        pkt.pts = av_rescale_q_rnd(pkt.pts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
        pkt.dts = pkt.pts;//av_rescale_q_rnd(pkt.dts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
        pkt.duration = av_rescale_q(pkt.duration, in_stream->time_base, out_stream->time_base);
        pkt.pos = -1;
        //Print to Screen
        if(pkt.stream_index == videoindex)
        {
            printf("Send %8d video frames to output URL\n",frame_index);
            frame_index++;
        }
        ret = av_interleaved_write_frame(ofmt_ctx, &pkt);

        if (ret < 0)
        {
            printf( "Error muxing packet\n");
            break;
        }
        av_free_packet(&pkt);

    }
    //Write file trailer
    av_write_trailer(ofmt_ctx);
    end:
    avformat_close_input(&ifmt_ctx);
    /* close output */
    if (ofmt_ctx && !(ofmt->flags & AVFMT_NOFILE))
        avio_close(ofmt_ctx->pb);
    avformat_free_context(ofmt_ctx);
    if (ret < 0 && ret != AVERROR_EOF)
    {
        printf( "Error occurred.\n");
        return -1;
    }
    return 0;
}

JNIEXPORT jboolean JNICALL Java_com_dftc_onvif_Onvif_initCamStream(
    JNIEnv *env, jobject obj, jint jid, jstring jurl)
{
    LOGI( "initCamStream start! \n");
    //
    if (!m_FFmpeg_Inited)
    {
        m_FFmpeg_Inited = TRUE;

        if (!InitAVFormatQueue(&m_AVFormatQueue))
            return JNI_FALSE;
#ifdef _DEBUG_
        av_log_set_callback(custom_log);
#endif
        av_register_all();
        LOGI( "avformat_network_init");
        //Network
        avformat_network_init();
        LOGI( "avformat_open_input");
    }

    char url[500] = { 0 };
    const char *curl = (*env)->GetStringUTFChars(env, jurl, NULL);
    sprintf(url, "%s", curl);
    (*env)->ReleaseStringUTFChars(env, jurl, curl);

    int i;
    AVCodecContext *pCodecCtx;
    AVCodec *pCodec;
    AVFrame *pFrame, *pFrameYUV;
    uint8_t *out_buffer;

    struct SwsContext *img_convert_ctx;

    AVFormatNode *pAVFormat = AllocAVFormat();
    pAVFormat->id = jid;

    AVFormatContext *pFormatCtx = avformat_alloc_context();

    pFormatCtx->interrupt_callback.callback = interrupt_cb; //--------注册回调函数
    pFormatCtx->interrupt_callback.opaque = pFormatCtx;

    AVDictionary* options = NULL;
    av_dict_set(&options, "rtsp_transport", "tcp", 0);

    if (avformat_open_input(&pFormatCtx, url, NULL, NULL) != 0) //打开网络流或文件流
    {
        LOGE("Couldn't open input stream.\n");
        FreeAVFormat(pAVFormat);
        return JNI_FALSE;
    }

    if (avformat_find_stream_info(pFormatCtx, NULL) < 0)
    {
        LOGE("Couldn't find stream information.\n");
        avformat_close_input(&pFormatCtx);
        FreeAVFormat(pAVFormat);
        return JNI_FALSE;
    }

    int videoindex = -1;
    for (i = 0; i < pFormatCtx->nb_streams; i++)
        if (pFormatCtx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO)
        {
            videoindex = i;
            break;
        }
    if (videoindex == -1)
    {
        LOGE("Didn't find a video stream.\n");
        avformat_close_input(&pFormatCtx);
        FreeAVFormat(pAVFormat);
        return JNI_FALSE;
    }

    pCodecCtx = pFormatCtx->streams[videoindex]->codec;
    pCodec = avcodec_find_decoder(pCodecCtx->codec_id);
    if (pCodec == NULL)
    {
        LOGE("Codec not found.\n");
        avformat_close_input(&pFormatCtx);
        FreeAVFormat(pAVFormat);
        return JNI_FALSE;
    }

    if (avcodec_open2(pCodecCtx, pCodec, NULL) < 0)
    {
        LOGE("Could not open codec.\n");
        avformat_close_input(&pFormatCtx);
        FreeAVFormat(pAVFormat);
        return JNI_FALSE;
    }

    pFrame = av_frame_alloc();
    pFrameYUV = av_frame_alloc();
    out_buffer = (uint8_t *) av_malloc(
                     avpicture_get_size(AV_PIX_FMT_YUV420P, pCodecCtx->width,
                                        pCodecCtx->height));
    avpicture_fill((AVPicture *) pFrameYUV, out_buffer, AV_PIX_FMT_YUV420P,
                   pCodecCtx->width, pCodecCtx->height);

    //Output Info---输出一些文件（RTSP）信息
    printf("---------------- File Information ---------------\n");
    av_dump_format(pFormatCtx, 0, url, 0);
    printf("-------------------------------------------------\n");

    img_convert_ctx = sws_getContext(pCodecCtx->width, pCodecCtx->height,
                                     pCodecCtx->pix_fmt, pCodecCtx->width, pCodecCtx->height,
                                     AV_PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);

    pAVFormat->videoindex = videoindex;
    pAVFormat->pFormatCtx = pFormatCtx;

    PushAVFormat(m_AVFormatQueue, pAVFormat);
    LOGI( "initCamStream finish! \n");
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_com_dftc_onvif_Onvif_closeCamStream(
    JNIEnv *env, jobject obj, jint id)
{

    AVFormatNode *pAVFormat;
    if (!PopAVFormatById(m_AVFormatQueue, &pAVFormat, id))
        return JNI_FALSE;
    FreeAVFormat(pAVFormat);
    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL Java_com_dftc_onvif_Onvif_getH264Stream(
    JNIEnv *env, jobject obj, jint id)
{

    AVFormatNode *pAVFormat;
    if (!GetAVFormatById(m_AVFormatQueue, &pAVFormat, id))
    {
        LOGE("GetAVFormatById error\n");
        return JNI_FALSE;
    }
    printf("GetAVFormatById finish\n");
    AVPacket *packet;
    int num = 0;
    while (TRUE)
    {
        packet = (AVPacket *) av_malloc(sizeof(AVPacket));
        printf("Call av_read_frame\n");
        m_read_frame_time_out = 0;
        m_read_frame = TRUE;
        if (av_read_frame(pAVFormat->pFormatCtx, packet) < 0)
        {
            m_read_frame = FALSE;
            LOGE("av_read_frame error\n");
            return NULL;
        }
        m_read_frame = FALSE;
        printf("Call av_read_frame finish!\n");
        if (packet->stream_index != pAVFormat->videoindex)
        {
            LOGE("Not video stream!\n");
#ifdef _DEBUG_
            LOGE("packet->data = %d,%d,%d,%d,%d\n",
                 packet->data[0], packet->data[1], packet->data[2], packet->data[3], packet->data[4]);
#endif
            av_free_packet(packet);
            if (num++ > 100)
            {
                LOGE("av_read_frame error : No video stream\n");
                return NULL;
            }
        }
        else
        {
            break;
        }
    }
    printf("av_read_frame finish\n");
    jbyte *by = (jbyte*) packet->data;
    jbyteArray jarray = (*env)->NewByteArray(env, packet->size);
    (*env)->SetByteArrayRegion(env, jarray, 0, packet->size, by);
    av_free_packet(packet);
    return jarray;
}

JNIEXPORT jint JNICALL Java_com_dftc_onvif_Onvif_connectRtmpSer(JNIEnv *env,
        jobject obj, jstring jserAddr)
{
    if (m_RtmpNodeQueue == NULL && !InitRtmpNodeQueue(&m_RtmpNodeQueue))
        return -1;
    char serAddr[500] = { 0 };
    const char *cserAddr = (*env)->GetStringUTFChars(env, jserAddr, NULL);
    sprintf(serAddr, "%s", cserAddr);
    (*env)->ReleaseStringUTFChars(env, jserAddr, cserAddr);

    RTMP *m_pRtmp = RTMP_Alloc();
    RTMP_Init(m_pRtmp);
    LOGI( "RTMP_Connect : %s \n", serAddr);
    m_pRtmp->Link.timeout = 5;
    // if (!RTMP_SetupURL2(m_pRtmp, lpAnsiURL, lpAnsiPlaypath))
    if (!RTMP_SetupURL(m_pRtmp, (char*) serAddr))
    {
        LOGE( "RTMP_SetupURL error \n");
        return -1;
    }
    RTMP_EnableWrite(m_pRtmp);

    ////////////////////////////////////////////////////////////////////////
    m_pRtmp->Link.swfUrl.av_len = m_pRtmp->Link.tcUrl.av_len;
    m_pRtmp->Link.swfUrl.av_val = m_pRtmp->Link.tcUrl.av_val;
    m_pRtmp->Link.flashVer.av_val = "FMLE/3.0 (compatible; FMSc/1.0)";
    m_pRtmp->Link.flashVer.av_len = (int)strlen(m_pRtmp->Link.flashVer.av_val);

    //m_pRtmp->m_outChunkSize = 4096;//RTMP_DEFAULT_CHUNKSIZE;//
    //m_pRtmp->m_bSendChunkSizeInfo = TRUE;

    //m_pRtmp->m_bUseNagle = TRUE;

    //------------------------------------------

//    int tcpBufferSize = 64*1024;
//
//    int curTCPBufSize, curTCPBufSizeSize = sizeof(curTCPBufSize);
//    getsockopt (m_pRtmp->m_sb.sb_socket, SOL_SOCKET, SO_SNDBUF, (char *)&curTCPBufSize, &curTCPBufSizeSize);
//    printf("SO_SNDBUF was at %u", curTCPBufSize);
//
//    if(curTCPBufSize < tcpBufferSize)
//    {
//        setsockopt (m_pRtmp->m_sb.sb_socket, SOL_SOCKET, SO_SNDBUF, (const char *)&tcpBufferSize, sizeof(tcpBufferSize));
//        getsockopt (m_pRtmp->m_sb.sb_socket, SOL_SOCKET, SO_SNDBUF, (char *)&curTCPBufSize, &curTCPBufSizeSize);
//        if(curTCPBufSize != tcpBufferSize)
//            printf("Could not set SO_SNDBUF to %u, value is now %u", tcpBufferSize, curTCPBufSize);
//    }
//
//    printf("SO_SNDBUF is now %u", tcpBufferSize);

    //------------------------------------------

    ////////////////////////////////////////////////////////////////////////

    RTMP_SetBufferMS(m_pRtmp, 3600 * 1000);
    if (!RTMP_Connect(m_pRtmp, NULL))
    {
        LOGE( "RTMP_Connect error \n");
        return -1;
    }
    if (!RTMP_ConnectStream(m_pRtmp, 0))
    {
        LOGE( "RTMP_ConnectStream error \n");
        return -1;
    }

    RtmpNode *p = AllocRtmpNode();
    p->id = m_SerIdIndex++;
    p->m_pRtmp = m_pRtmp;
    PushRtmpNode(m_RtmpNodeQueue, p);

    return p->id;
}

JNIEXPORT jboolean JNICALL Java_com_dftc_onvif_Onvif_disconnectRtmpSer(
    JNIEnv *env, jobject obj, jint id)
{
    RtmpNode *pRtmpNode;
    if (!PopRtmpNodeById(m_RtmpNodeQueue, &pRtmpNode, id))
        return JNI_FALSE;
    FreeRtmpNode(pRtmpNode);
    return JNI_TRUE;
}

BOOL SendSpsPps(RTMP *pRtmp, char* h264, int length, int width, int height,
                int rate)
{
    RTMPMetadata metaData;
    memset(&metaData, 0, sizeof(RTMPMetadata));

    if (!GainSpsPps(metaData.Sps, &metaData.nSpsLen, metaData.Pps,
                    &metaData.nPpsLen, h264, length))
        return FALSE;
    metaData.nWidth = width; //352; //1920;
    metaData.nHeight = height; //288; //1080;
    metaData.nFrameRate = rate; //25;
    printf("width ,height, framerate:%d,%d,%d\n", metaData.nWidth,
           metaData.nHeight, metaData.nFrameRate);
    printf("sps_len, pps_len: %d,%d  \n", metaData.nSpsLen, metaData.nPpsLen);

    return SendMetadata(pRtmp, &metaData);
}

JNIEXPORT jboolean JNICALL Java_com_dftc_onvif_Onvif_sendSpsPps(JNIEnv *env,
        jobject obj, jint id, jbyteArray jh264, jint jlength, jint jwidth,
        jint jheight, jint jrate)
{
    RtmpNode *pRtmpNode;
    if (!GetRtmpNodeById(m_RtmpNodeQueue, &pRtmpNode, id))
        return JNI_FALSE;
    printf("GetRtmpNodeById finish! \n");
//    if (!pRtmpNode->m_SendSpsPps)
//    {
        jbyte* h264 = (*env)->GetByteArrayElements(env, jh264, 0);
        if (!SendSpsPps(pRtmpNode->m_pRtmp, h264, jlength, jwidth, jheight,
                        jrate))
        {
            (*env)->ReleaseByteArrayElements(env, jh264, h264, 0);
            return JNI_FALSE;
        }
        (*env)->ReleaseByteArrayElements(env, jh264, h264, 0);
        pRtmpNode->width = jwidth;
        pRtmpNode->height = jheight;
        pRtmpNode->rate = jrate;
        pRtmpNode->m_SendSpsPps = TRUE;
//    }
    return JNI_TRUE;
}

//unsigned char *keyFramebuf = NULL;
//int keyFramesize;
//int keyFrametick;

JNIEXPORT jboolean JNICALL Java_com_dftc_onvif_Onvif_annexH264(JNIEnv *env,
        jobject obj, jint id, jbyteArray jh264, jint jlength, jint jtick)
{
    RtmpNode *pRtmpNode;
    if (!GetRtmpNodeById(m_RtmpNodeQueue, &pRtmpNode, id))
        return JNI_FALSE;
    printf("GetRtmpNodeById finish! \n");
    if (!pRtmpNode->m_SendSpsPps)
    {
        return JNI_FALSE;
    }
    else
    {
        jbyte* h264 = (*env)->GetByteArrayElements(env, jh264, 0);
        unsigned char *framebuf = NULL;
        int framesize = 0;
        BOOL Is_KyeFrame;
        framesize = Read_One_H264_Frame(&framebuf, h264, jlength, &Is_KyeFrame);
        if (framesize == 0)
        {
            LOGE("Read_One_H264_Frame error! \n");
            if (!framebuf)
                free(framebuf);
            (*env)->ReleaseByteArrayElements(env, jh264, h264, 0);
            return JNI_FALSE;
        }
        else if (framesize == -1)
        {
//            LOGE("Handler SPS PPS \n");
//            if(SendSpsPps(pRtmpNode->m_pRtmp, h264, jlength, pRtmpNode->width, pRtmpNode->height,
//                       pRtmpNode->rate))
//            {
//                LOGE("Handler SPS PPS complete! \n");
//            }
//
//            (*env)->ReleaseByteArrayElements(env, jh264, h264, 0);
            return JNI_TRUE;
        }

//        if(Is_KyeFrame){
//            if(!keyFramebuf)
//                free(keyFramebuf);
//            keyFrametick = jtick;
//            keyFramesize = framesize;
//            keyFramebuf = (unsigned char*) calloc(keyFramesize, sizeof(char));
//            memcpy(keyFramebuf, framebuf, keyFramesize);
//        }
//        else{
//            if(keyFramebuf && jtick - keyFrametick > 1000){
//                SendH264Packet(pRtmpNode->m_pRtmp, keyFramebuf, keyFramesize,
//                               TRUE, jtick);
//            }
//
//        }


        printf("Read_One_H264_Frame finish! \n");
        if (!SendH264Packet(pRtmpNode->m_pRtmp, framebuf, framesize,
                            Is_KyeFrame, jtick))
        {
            LOGE("SendH264Packet error! \n");
            free(framebuf);
            (*env)->ReleaseByteArrayElements(env, jh264, h264, 0);
            return JNI_FALSE;
        }
        printf("SendH264Packet finish! \n");
        free(framebuf);
        (*env)->ReleaseByteArrayElements(env, jh264, h264, 0);
    }

    return JNI_TRUE;
}

