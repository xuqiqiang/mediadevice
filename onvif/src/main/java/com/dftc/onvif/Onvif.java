package com.dftc.onvif;

import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.util.Log;

import com.alibaba.sdk.android.oss.common.OSSLog;
import com.alibaba.sdk.android.vod.upload.VODUploadCallback;
import com.alibaba.sdk.android.vod.upload.VODUploadClient;
import com.alibaba.sdk.android.vod.upload.model.UploadFileInfo;
import com.dftc.onvif.finder.CameraDevice;
import com.dftc.onvif.utils.Cache;
import com.dftc.onvif.view.DesktopLayout;
import com.dftc.onvif.view.VideoPlayerActivity;

import org.videolan.libvlc.LibVLC;
import org.videolan.libvlc.LibVlcException;
import org.videolan.libvlc.Util;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Onvif {
    public static final String TAG = "Onvif";

    static {
        System.loadLibrary("ijkffmpeg");
        System.loadLibrary("sffstreamer");
    }

    public static final String USERNAME = "admin";
    public static final String PASSWORD = "888888";

    public static final String DEVICE_UUID = "386d43c9-1787-49f8-bfb4-11280f7579d9";
    public static final String DEVICE_URL = "http://%s:%d/onvif/device_service";

    public static final String DIR_NAME = "video";

    public static final long TIMEOUT = 10000;

    private static String accessKeyId = "LTAI7lMEXjSNG024";
    private static String accessKeySecret = "k3SSXH9oL9UllJk9GKsfTwe4KhOnvL";
    private static String endpoint = "http://oss-cn-hangzhou.aliyuncs.com";
    private static String bucket = "testdftciii";
    private static VODUploadClient mVODUploadClient;

    private static boolean isRunning;

    public interface OnRecordListener {
        public void onComplete(String filePath);
    }

    public static void init(Context context) {
        if (mVODUploadClient == null) {
            if (BuildConfig.DEBUG)
                OSSLog.enableLog();
            mVODUploadClient = new VODUploadClient(context);
            VODUploadCallback callback = new VODUploadCallback() {
                @Override
                public void onUploadSucceed(UploadFileInfo info) {
                    Log.d(TAG, "onUploadSucceed: " + info.getFilePath());
                }

                @Override
                public void onUploadFailed(UploadFileInfo info, String code,
                                           String message) {
                    Log.d(TAG, "onUploadFailed: " + info.getFilePath()
                            + ",code:" + code + ",message:" + message);
                }

                @Override
                public void onUploadProgress(UploadFileInfo info,
                                             long uploadedSize, long totalSize) {
                    Log.d(TAG, "onUploadProgress: " + info.getFilePath()
                            + ", progress:" + uploadedSize * 100 / totalSize);
                }

                @Override
                public void onUploadTokenExpired() {
                    Log.d(TAG, "onUploadTokenExpired");
                }
            };
            mVODUploadClient.init(accessKeyId, accessKeySecret, callback);
        }
    }

    public static void upload(String filePath, String name) {
        if (mVODUploadClient != null) {
            mVODUploadClient.addFile(filePath, endpoint, bucket, name);
            mVODUploadClient.startUpload();
        }
    }

    public static void connect(final Context context, final String devIP,
                               final int devPort, final Runnable r) {
    }

    public static void connect(final Context context, final String devIP,
                               final int devPort) {
        connect(context, devIP, devPort, new Runnable() {

            @Override
            public void run() {
                Intent intent = new Intent();
                intent.setClass(context, VideoPlayerActivity.class);
                intent.putExtra("name", devIP + ":" + devPort);
                context.startActivity(intent);
            }
        });
    }

    public static void record(final Context context, final String devIP,
                              final int devPort, final long time, final OnRecordListener listener) {
        connect(context, devIP, devPort, new Runnable() {

            @Override
            public void run() {

                new Handler().postDelayed(new Runnable() {

                    @Override
                    public void run() {

                        DesktopLayout mDesktopLayout = new DesktopLayout(
                                context);
                        mDesktopLayout.setEvent(new Runnable() {

                            @Override
                            public void run() {
                                LibVLC mLibVLC = null;
                                try {
                                    mLibVLC = Util.getLibVlcInstance();
                                } catch (LibVlcException e2) {
                                    e2.printStackTrace();
                                }
                                Cache.getInstance(context);
                                Cache.createDir(DIR_NAME);
                                SimpleDateFormat df = new SimpleDateFormat(
                                        "yyyy-MM-dd HH-mm-ss");
                                String filePath = Cache
                                        .getRealFilePath(DIR_NAME
                                                + File.separator
                                                + df.format(new Date()));
                                long waitTime = 0;
                                while (true) {
                                    try {
                                        if (waitTime > TIMEOUT) {
                                            listener.onComplete(null);
                                            return;
                                        }
                                        if (mLibVLC.videoIsRecording()) {
                                            break;
                                        } else {
                                            mLibVLC.videoRecordStart(filePath);
                                            Log.d(TAG, "call videoRecordStart");
                                        }
                                        Thread.sleep(1000);
                                        waitTime += 1000;
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                }
                                Log.d(TAG, "start record");
                                try {
                                    Thread.sleep(time);
                                } catch (InterruptedException e1) {
                                    e1.printStackTrace();
                                }
                                Log.d(TAG, "record finished");
                                waitTime = 0;
                                while (true) {
                                    try {
                                        if (waitTime > TIMEOUT) {
                                            listener.onComplete(null);
                                            return;
                                        }
                                        if (!mLibVLC.videoIsRecording()) {
                                            if (listener != null)
                                                listener.onComplete(filePath
                                                        + ".mp4");
                                            return;
                                        } else {
                                            mLibVLC.videoRecordStop();
                                            Log.d(TAG, "call videoRecordStop");
                                        }
                                        Thread.sleep(1000);
                                        waitTime += 1000;
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        });
                        mDesktopLayout.showDesk();
                    }
                }, 2000);

            }
        });
    }

    public static void upload(final Context context, final String devIP,
                              final int devPort) {

//        String url = String.format(DEVICE_URL, devIP, devPort);
//        CameraDevice cd = new CameraDevice(UUID.fromString(DEVICE_UUID), url,
//                false);
//        cd.setOnline(true);
//
//        cd.setSecurity(USERNAME, PASSWORD);
//
//        cd.setOnSoapDoneListener(new OnSoapDoneListener() {
//
//            @Override
//            public void onSoapDone(final CameraDevice device, boolean success) {
//                if (success) {
//                    new Thread() {
//                        public void run() {
//                            new Onvif().stream(device.getRtspUrl(),
//                                    "rtmp://ossrs.net/dtu/1187b");
//                            // new
//                            // Onvif().stream(uri,"rtmp://video-center.alivecdn.com/AppName/StreamName?vhost=test.sincerest.net");
//                        }
//                    }.start();
//
//                    /*
//                     * try { execCommand("/system/123/arm/lib/ffmpeg ");
//                     * //execCommand("/system/123/arm/lib/ffmpeg -i \"" + uri +
//                     * "\" -f flv -r 25 -s 640x480 -an \"rtmp://video-center.alivecdn.com/AppName/StreamName?vhost=dftcgroup.com\""
//                     * ); } catch (IOException e) { // TODO Auto-generated catch
//                     * block e.printStackTrace(); } FFmpegManager manager=new
//                     * FFmpegManagerImpl(10); //组装命令 Map map = new HashMap();
//                     * map.put("appName", "test123"); map.put("input",
//                     * "rtsp://admin:admin@192.168.2.236:37779/cam/realmonitor?channel=1&subtype=0"
//                     * ); map.put("output", "rtmp://192.168.30.21/live/");
//                     * map.put("codec","h264"); map.put("fmt", "flv");
//                     * map.put("fps", "25"); map.put("rs", "640x360");
//                     * map.put("twoPart","2");
//                     *
//                     * //执行任务，id就是appName，如果执行返回为null String
//                     * id=manager.start(map); Log.d(TAG, "id:" + id);
//                     * System.out.println(id);
//                     */
//                }
//
//            }
//        });
//        cd.IPCamInit();
    }

    public static String execCommand(String command) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        Process proc = runtime.exec(command);

        try {
            if (proc.waitFor() != 0) {
                Log.d("execInstall", "exit value = " + proc.exitValue());
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        InputStream inputstream = proc.getInputStream();
        InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
        BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
        // read the ls output
        String line = "";
        StringBuilder sb = new StringBuilder(line);
        while ((line = bufferedreader.readLine()) != null) {
            sb.append(line);
            sb.append('\n');
        }

        Log.d(TAG, "execCommand result = " + sb.toString());

        return sb.toString();

    }

    // JNI
    //public native List<Camera> scanForCamera();

    //public native int stream(String inputurl, String outputurl);

    // cameraplayAddress 是摄像头播放地址，socketNum是本地通过upd接受摄像头 数据的端口
//    public void connectCam(String cameraPlayAddresss, int socketNum,
//            boolean mainRate, final OnSoapDoneListener listener) {
//        String url = String.format(DEVICE_URL, cameraPlayAddresss, socketNum);
//        Log.d(TAG, "mainRate : " + mainRate);
//        CameraDevice cd = new CameraDevice(UUID.fromString(DEVICE_UUID), url,
//                mainRate);
//        cd.setOnline(true);
//
//        cd.setSecurity(USERNAME, PASSWORD);
//
//        cd.setOnSoapDoneListener(new OnSoapDoneListener() {
//
//            @Override
//            public void onSoapDone(CameraDevice device, boolean success) {
//                if (success) {
//                    success = initCamStream(device.getId(), device.getRtspUrl());
//                }
//                listener.onSoapDone(device, success);
//            }
//        });
//        cd.IPCamInit();
//    }

    public native boolean initCamStream(int id, String url);

    // 断开摄像头发送流
    public void disconnectCam(CameraDevice device) {
        closeCamStream(device.getId());
    }

    private native boolean closeCamStream(int id);

    // 取得摄像头发送流
    public byte[] getH264Stream(CameraDevice device) {
        return getH264Stream(device.getId());
    }

    private native byte[] getH264Stream(int id);

    public native int connectRtmpSer(String serAddr); // 连接rtmp服务器

    public native boolean disconnectRtmpSer(int serId); // 断开rtmp服务器

    public boolean sendSpsPps(int serId, byte[] h264, CameraDevice device) {
        return sendSpsPps(serId, h264, h264.length, device.width,
                device.height, device.rate);
    }

    private native boolean sendSpsPps(int serId, byte[] h264, int length,
                                      int width, int height, int frameRate); // 推送帧数据

    public boolean annexH264(int serId, byte[] h264, int tick) {
        return annexH264(serId, h264, h264.length, tick);
    }

    private native boolean annexH264(int serId, byte[] h264, int length,
                                     int tick); // 推送帧数据

    public void testPush(final Context context, final String devIP,
                         final int devPort) {
//        connectCam(devIP, devPort, false, new OnSoapDoneListener() {
//
//            @Override
//            public void onSoapDone(final CameraDevice device, boolean success) {
//                if (success) {
//                    new Thread() {
//                        public void run() {
//                            int serId = connectRtmpSer("rtmp://ossrs.net/dtu/1187b");
//                            long start = System.currentTimeMillis();
//                            int tick = 0;
//                            boolean sendSpsPps = false;
//                            while (true) {
//
//                                if (!sendSpsPps) {
//                                    while (true) {
//                                        byte[] h264 = getH264Stream(device);
//                                        if (annexH264(serId, h264, h264.length,
//                                                tick))
//                                            break;
//                                    }
//                                    sendSpsPps = true;
//                                    tick = 0;
//                                }
//                                byte[] h264 = getH264Stream(device);
//
//                                annexH264(serId, h264, h264.length, tick);
//                                long now = System.currentTimeMillis();
//
//                                long time = 67 - (now - start);
//                                start = now;
//                                if (time > 0) {
//                                    try {
//                                        sleep(time);
//                                    } catch (InterruptedException e) {
//                                        // TODO Auto-generated catch block
//                                        e.printStackTrace();
//                                    }
//
//                                }
//                                tick += 67;
//                            }
//
//                        }
//                    }.start();
//                }
//            }
//        });
    }

}