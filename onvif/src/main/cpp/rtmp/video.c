#include "video.h"

NALU_t *AllocNALU(int buffersize)
{
    NALU_t *n;

    if ((n = (NALU_t*) calloc(1, sizeof(NALU_t))) == NULL)
    {
        LOGE("AllocNALU Error: Allocate Meory To NALU_t error ");
        getchar();
    }

    n->max_size = buffersize; //Assign buffer size

    if ((n->buf = (unsigned char*) calloc(buffersize, sizeof(char))) == NULL)
    {
        free(n);
        LOGE("AllocNALU Error: Allocate Meory To NALU_t Buffer error ");
        getchar();
    }
    return n;
}

void FreeNALU(NALU_t *n)
{
    if (n)
    {
        if (n->buf)
        {
            free(n->buf);
            n->buf = NULL;
        }
        free(n);
    }
}

BOOL FindStartCode2(unsigned char *Buf)
{
    if (Buf[0] != 0 || Buf[1] != 0 || Buf[2] != 1) //Check whether buf is 0x000001
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

BOOL FindStartCode3(unsigned char *Buf)
{
    if (Buf[0] != 0 || Buf[1] != 0 || Buf[2] != 0 || Buf[3] != 1) //Check whether buf is 0x00000001
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

int ReadChar(unsigned char * to, unsigned char * from, int sum)
{
    int i;
    for (i = 0; i < sum; i++)
    {
        to[i] = from[i];
    }
    return sum;
}

int GetAnnexbNALU(NALU_t * nalu, char* data, int size, int *Buf_index)
{
    if (*Buf_index >= size)
    {
        LOGE( "GetAnnexbNALU Buf_index error!\n");
        return 0;
    }
    if (FindStartCode2(data + *Buf_index))
    {
        nalu->startcodeprefix_len = 3; //初始化前缀位三个字节
    }
    else if (FindStartCode3(data + *Buf_index))
    {
        nalu->startcodeprefix_len = 4; //初始化前缀位三个字节
    }
    else
    {
        LOGE( "GetAnnexbNALU data error!\n");
        return 0;
    }

    int i;

    int End_index;
    for (i = *Buf_index + nalu->startcodeprefix_len; i < size - 4; i++)
    {
        if (FindStartCode2(data + i) || FindStartCode3(data + i))
        {
            break;
        }
    }
    End_index = i;
    if (End_index >= size - 4)
        End_index = size;
    else
    {
        LOGI( "Found SPS PPS \n");
    }

#ifdef _DEBUG_
    char* str = malloc(size * 2 + 1);
    for (i = 0; i < End_index - *Buf_index; i++)
    {
        str[i * 2] = data[i + *Buf_index] + '0';
        str[i * 2 + 1] = ',';
    }
    str[i * 2] = '\0';
    LOGI( "size:%d \n", size);
    LOGI( "data:%s \n", str);
    free(str);

    printf("nalu->startcodeprefix_len = %d\n", nalu->startcodeprefix_len);
    printf("data = %d,%d,%d,%d,%d\n", data[*Buf_index], data[*Buf_index + 1],
           data[*Buf_index + 2], data[*Buf_index + 3], data[*Buf_index + 4]);
#endif

    nalu->len = End_index - *Buf_index - nalu->startcodeprefix_len; //设置包含nal 头的数据长度
    memcpy(nalu->buf, &data[*Buf_index + nalu->startcodeprefix_len], nalu->len); //拷贝一个nal 数据到数组中
    nalu->forbidden_bit = nalu->buf[0] & 0x80; //1 bit  设置nal 头
    nalu->nal_reference_idc = nalu->buf[0] & 0x60; // 2 bit
    nalu->nal_unit_type = (nalu->buf[0]) & 0x1f; // 5 bit
    printf("nal_unit_type = %d\n", nalu->nal_unit_type);
    if (End_index >= size - 4)
    {
        *Buf_index = size;
    }
    else
        *Buf_index = End_index;
    return nalu->startcodeprefix_len; //((info3 == 1)? 4 : 3);
}

int GetFrameType(NALU_t * nal)
{
    bs_t s;
    int frame_type = 0;
    unsigned char * OneFrameBuf_H264 = NULL;
    if ((OneFrameBuf_H264 = (unsigned char *) calloc(nal->len + 4,
                            sizeof(unsigned char))) == NULL)
    {
        LOGE("Error malloc OneFrameBuf_H264\n");
        return getchar();
    }
    if (nal->startcodeprefix_len == 3)
    {
        OneFrameBuf_H264[0] = 0x00;
        OneFrameBuf_H264[1] = 0x00;
        OneFrameBuf_H264[2] = 0x01;
        memcpy(OneFrameBuf_H264 + 3, nal->buf, nal->len);
    }
    else if (nal->startcodeprefix_len == 4)
    {
        OneFrameBuf_H264[0] = 0x00;
        OneFrameBuf_H264[1] = 0x00;
        OneFrameBuf_H264[2] = 0x00;
        OneFrameBuf_H264[3] = 0x01;
        memcpy(OneFrameBuf_H264 + 4, nal->buf, nal->len);
    }
    else
    {
        LOGE("H264 error！\n");
    }
    bs_init(&s, OneFrameBuf_H264 + nal->startcodeprefix_len + 1, nal->len - 1);

    if (nal->nal_unit_type == NAL_SLICE
            || nal->nal_unit_type == NAL_SLICE_IDR)
    {
        /* i_first_mb */
        bs_read_ue(&s);
        /* picture type */
        frame_type = bs_read_ue(&s);
        switch (frame_type)
        {
        case 0:
        case 5: /* P */
            nal->Frametype = FRAME_P;
            break;
        case 1:
        case 6: /* B */
            nal->Frametype = FRAME_B;
            break;
        case 3:
        case 8: /* SP */
            nal->Frametype = FRAME_P;
            break;
        case 2:
        case 7: /* I */
            nal->Frametype = FRAME_I;
            break;
        case 4:
        case 9: /* SI */
            nal->Frametype = FRAME_I;
            break;
        }
    }
    else if (nal->nal_unit_type == NAL_SEI)
    {
        nal->Frametype = NAL_SEI;
    }
    else if (nal->nal_unit_type == NAL_SPS)
    {
        nal->Frametype = NAL_SPS;
    }
    else if (nal->nal_unit_type == NAL_PPS)
    {
        nal->Frametype = NAL_PPS;
    }
    if (OneFrameBuf_H264)
    {
        free(OneFrameBuf_H264);
        OneFrameBuf_H264 = NULL;
    }
    return 1;
}

BOOL GainSpsPps(unsigned char * spsbuf, unsigned int * spslength,
                unsigned char * ppsbuf, unsigned int * ppslength, char* data, int size)
{
    //读取二帧数据
    NALU_t * n_1 = NULL;
    NALU_t * n_2 = NULL;
    unsigned int avcc_pos;
    n_1 = AllocNALU(MAX_VIDEO_TAG_BUF_SIZE);
    n_2 = AllocNALU(MAX_VIDEO_TAG_BUF_SIZE);
    int Buf_index = 0;
loop_1_1:
    printf("loop_1_1\n");
    if (Buf_index >= size)
    {
        LOGE("loop_1_1 error\n");
        return FALSE;
    }
    if (GetAnnexbNALU(n_1, data, size, &Buf_index) == 0)
        return FALSE;
    //判断帧类型
    GetFrameType(n_1);
    if (n_1->nal_unit_type == NAL_SPS)
    {
loop_1_2:
        printf("loop_1_2\n");
        if (Buf_index >= size)
        {
            LOGE("loop_1_2 error\n");
            return FALSE;
        }
        if (GetAnnexbNALU(n_2, data, size, &Buf_index) == 0)
            return FALSE;
        //判断帧类型
        GetFrameType(n_2);
        if (n_2->nal_unit_type == NAL_PPS)
        {
            memcpy(spsbuf, n_1->buf, n_1->len);
            *spslength = n_1->len;
            memcpy(ppsbuf, n_2->buf, n_2->len);
            *ppslength = n_2->len;
        }
        else
        {
            goto loop_1_2;
        }
    }
    else
    {
        goto loop_1_1;
    }
    FreeNALU(n_1);
    FreeNALU(n_2);
    return TRUE;
}

int Read_One_H264_Frame(unsigned char ** buf, char* data, int size,
                        int *Is_KyeFrame)
{
    NALU_t * n = NULL;
    int startcodeprefix_size;
    unsigned int video_buf_size = 0;
    *Is_KyeFrame = FALSE;
    //分配nal 资源
    n = AllocNALU(MAX_VIDEO_TAG_BUF_SIZE);
    int Buf_index = 0;

loop_2:
    //读取一帧数据
    if (Buf_index >= size)
    {
        LOGE("loop_2 error\n");
        return 0;
    }
    startcodeprefix_size = GetAnnexbNALU(n, data, size, &Buf_index);
    if (startcodeprefix_size == 0)
    {
        printf("loop_1_2 error \n");
        return 0;
    }
    //判断帧类型
    GetFrameType(n);

    if (n->Frametype == FRAME_I)
    {
        //将data填入bufz中
#if 0
        buf[0] = n->len >> 24;
        buf[1] = (n->len >> 16) & 0xFF;
        buf[2] = (n->len >> 8) & 0xFF;
        buf[3] = n->len & 0xFF;
        memcpy(buf + 4 ,n->buf,n->len);
        video_buf_size = n->len + 4;
#endif
        *Is_KyeFrame = TRUE;
        *buf = (unsigned char*) calloc(n->len, sizeof(char));
        memcpy(*buf, n->buf, n->len);
        video_buf_size = n->len;
        LOGE("Is_KyeFrame\n");

    }
    else if (n->Frametype == FRAME_B || n->Frametype == FRAME_P)
    {
#if 0
        buf[0] = n->len >> 24;
        buf[1] = (n->len >> 16) & 0xFF;
        buf[2] = (n->len >> 8) & 0xFF;
        buf[3] = n->len & 0xFF;
        memcpy(buf + 4 ,n->buf,n->len);
        video_buf_size = n->len + 4;
#endif
        *buf = (unsigned char*) calloc(n->len, sizeof(char));
        memcpy(*buf, n->buf, n->len);
        video_buf_size = n->len;
        LOGE("!Is_KyeFrame, %d\n", n->Frametype);
    }
//    else if (n->Frametype == NAL_SPS || n->Frametype == NAL_PPS)
//    {
//        return -1;
//    }
    else   //其它帧直接去掉
    {
        goto loop_2;
    }

    FreeNALU(n); //释放nal 资源
    return video_buf_size;
}

