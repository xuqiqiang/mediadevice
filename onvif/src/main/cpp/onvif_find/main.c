/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *    Description:  客户端通过ONVIF协议搜索前端设备
 *       Compiler:  arm-linux-androideabi-gcc
 *
 * =====================================================================================
 */
#include "wsdd.h"
#include "platform.h"
//#include <stdio.h>

jclass list_cls = NULL;
jmethodID list_add = NULL;

static struct soap* ONVIF_Initsoap(struct SOAP_ENV__Header *header,
        const char *was_To, const char *was_Action, int timeout) {
    struct soap *soap = NULL;
    unsigned char macaddr[6];
    char _HwId[1024];
    unsigned int Flagrand;
    soap = soap_new();
    if (soap == NULL) {
        printf("[%d]soap = NULL\n", __LINE__);
        return NULL;
    }
    soap_set_namespaces(soap, namespaces);
    //超过5秒钟没有数据就退出
    if (timeout > 0) {
        soap->recv_timeout = timeout;
        soap->send_timeout = timeout;
        soap->connect_timeout = timeout;
    } else {
        //如果外部接口没有设备默认超时时间的话，我这里给了一个默认值10s
        soap->recv_timeout = 10;
        soap->send_timeout = 10;
        soap->connect_timeout = 10;
    }
    soap_default_SOAP_ENV__Header(soap, header);

    // 为了保证每次搜索的时候MessageID都是不相同的！因为简单，直接取了随机值
    srand((int) time(0));
    Flagrand = rand() % 9000 + 1000; //保证四位整数
    macaddr[0] = 0x1;
    macaddr[1] = 0x2;
    macaddr[2] = 0x3;
    macaddr[3] = 0x4;
    macaddr[4] = 0x5;
    macaddr[5] = 0x6;
    sprintf(_HwId, "urn:uuid:%ud68a-1dd2-11b2-a105-%02X%02X%02X%02X%02X%02X",
            Flagrand, macaddr[0], macaddr[1], macaddr[2], macaddr[3],
            macaddr[4], macaddr[5]);
    header->wsa__MessageID = (char *) malloc(100);
    memset(header->wsa__MessageID, 0, 100);
    strncpy(header->wsa__MessageID, _HwId, strlen(_HwId));

    if (was_Action != NULL) {
        header->wsa__Action = (char *) malloc(1024);
        memset(header->wsa__Action, '\0', 1024);
        strncpy(header->wsa__Action, was_Action, 1024); //"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
    }
    if (was_To != NULL) {
        header->wsa__To = (char *) malloc(1024);
        memset(header->wsa__To, '\0', 1024);
        strncpy(header->wsa__To, was_To, 1024); //"urn:schemas-xmlsoap-org:ws:2005:04:discovery";
    }
    soap->header = header;
    return soap;
}

jobject createCamera(JNIEnv *env, char *XAddrs, char *Address) {
    //获取java的Class
    jclass camera_cls = (*env)->FindClass(env, "com/dftc/onvif/finder/Camera");
    //获取java的Camera构造方法id---构造函数的函数名为<init>，返回值为void
    jmethodID camera_costruct = (*env)->GetMethodID(env, camera_cls, "<init>",
            "(Ljava/lang/String;ILjava/lang/String;)V"); //（类,属性名.签名)
    int i, XAddrs_len = strlen(XAddrs);
    int ip_start = -1, ip_end = -1;
    int port_start = -1, port_end = -1;
    for (i = 0; i < XAddrs_len; i++) {
        if (XAddrs[i] == ':') {
            if (ip_start == -1)
                ip_start = i + 3;
            else {
                ip_end = i;
                port_start = i + 1;
            }

        } else if (XAddrs[i] == '/') {
            if (port_start != -1) {
                port_end = i;
                break;
            }

        }
    }

    char str_ip[100], str_port[100];
    strncpy(str_ip, XAddrs + ip_start, ip_end - ip_start);
    str_ip[ip_end - ip_start] = '\0';
    strncpy(str_port, XAddrs + port_start, port_end - port_start);
    str_port[port_end - port_start] = '\0';

    char *str_uuid = strstr(Address, "uuid:") + 5;
    //创建Camera对象--使用NewObject方法
    jobject camera = (*env)->NewObject(env, camera_cls, camera_costruct,
            (*env)->NewStringUTF(env, str_ip), atoi(str_port),
            (*env)->NewStringUTF(env, str_uuid));
    return camera;
}

int ONVIF_ClientDiscovery(JNIEnv *env, jobject list_obj) {

//    (*env)->CallBooleanMethod(env,
//                                list_obj,
//                                list_add,
//                                createCamera(env, "http://192.168.2.82:8888/onvif/device_service",
//                                        "urn:uuid:adbcdefg")); //执行Arraylist类实例的add方法，添加一个stu对象
//    return 0;

    int HasDev = 0;
    int retval = SOAP_OK;
    wsdd__ProbeType req;
    struct __wsdd__ProbeMatches resp;
    wsdd__ScopesType sScope;
    struct SOAP_ENV__Header header;
    struct soap* soap;

    const char *was_To = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
    const char *was_Action =
            "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
    //这个就是传递过去的组播的ip地址和对应的端口发送广播信息
    const char *soap_endpoint = "soap.udp://239.255.255.250:3702/";

    //这个接口填充一些信息并new返回一个soap对象，本来可以不用额外接口，
    // 但是后期会作其他操作，此部分剔除出来后面的操作就相对简单了,只是调用接口就好
    soap = ONVIF_Initsoap(&header, was_To, was_Action, 5);

    soap_default_SOAP_ENV__Header(soap, &header);
    soap->header = &header;

    soap_default_wsdd__ScopesType(soap, &sScope);
    sScope.__item = "";
    soap_default_wsdd__ProbeType(soap, &req);
    req.Scopes = &sScope;
    req.Types = ""; //"dn:NetworkVideoTransmitter";

    retval = soap_send___wsdd__Probe(soap, soap_endpoint, NULL, &req);
    //发送组播消息成功后，开始循环接收各位设备发送过来的消息
    while (retval == SOAP_OK) {
        retval = soap_recv___wsdd__ProbeMatches(soap, &resp);
        if (retval == SOAP_OK) {
            if (soap->error) {
                printf("[%d]: recv soap error :%d, %s, %s\n", __LINE__,
                        soap->error, *soap_faultcode(soap),
                        *soap_faultstring(soap));
                retval = soap->error;
            } else //成功接收某一个设备的消息
            {
                HasDev++;
                if (resp.wsdd__ProbeMatches->ProbeMatch != NULL
                        && resp.wsdd__ProbeMatches->ProbeMatch->XAddrs
                                != NULL) {
                    printf(" ################  recv  %d devices info #### \n",
                            HasDev);
                    printf("Target Service Address  : %s\r\n",
                            resp.wsdd__ProbeMatches->ProbeMatch->XAddrs);
                    printf("Target EP Address       : %s\r\n",
                            resp.wsdd__ProbeMatches->ProbeMatch->wsa__EndpointReference.Address);
                    printf("Target Type             : %s\r\n",
                            resp.wsdd__ProbeMatches->ProbeMatch->Types);
                    printf("Target Metadata Version : %d\r\n",
                            resp.wsdd__ProbeMatches->ProbeMatch->MetadataVersion);
                    //sleep(1);
                    //或得Arraylist类中的 add()方法ID，其方法原型为： boolean add(Object object) ;

                    (*env)->CallBooleanMethod(env, list_obj, list_add,
                            createCamera(env,
                                    resp.wsdd__ProbeMatches->ProbeMatch->XAddrs,
                                    resp.wsdd__ProbeMatches->ProbeMatch->wsa__EndpointReference.Address)); //执行Arraylist类实例的add方法，添加一个stu对象
                }
            }
        } else if (soap->error) {
            if (HasDev == 0) {
                printf(
                        "[%s][%s][Line:%d] Thers Device discovery or soap error: %d, %s, %s \n",
                        __FILE__, __func__, __LINE__, soap->error,
                        *soap_faultcode(soap), *soap_faultstring(soap));
                retval = soap->error;
            } else {
                printf(" [%s]-[%d] Search end! It has Searched %d devices! \n",
                        __func__, __LINE__, HasDev);
                retval = 0;
            }
            break;
        }
    }

    soap_destroy(soap);
    soap_end(soap);
    soap_free(soap);

    return HasDev; //retval;
}

JNIEXPORT jobject JNICALL Java_com_dftc_onvif_LibOnvif_scanForCamera(
        JNIEnv *env, jobject obj) {
    if (list_cls == NULL)
        list_cls = (*env)->FindClass(env, "java/util/ArrayList"); //获得ArrayList类引用
    if (list_cls == NULL) {
        printf("list_cls is null \n");
        return NULL;
    }
    if (list_add == NULL)
        list_add = (*env)->GetMethodID(env, list_cls, "add",
                "(Ljava/lang/Object;)Z");

    jmethodID list_costruct = (*env)->GetMethodID(env, list_cls, "<init>",
            "()V"); //获得得构造函数Id

    jobject list_obj = (*env)->NewObject(env, list_cls, list_costruct); //创建一个Arraylist集合对象

    ONVIF_ClientDiscovery(env, list_obj);
    return list_obj;
}
