/**
 * Copyright (C) 2015 Fernando Cejas Open Source Project
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dftc.mediadevice.data.net;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;

import com.dftc.libonvif.OnvifUtil;
import com.dftc.libonvif.model.CameraInfomation;
import com.dftc.libonvif.model.ControlMessage;
import com.dftc.mediadevice.data.exception.CameraConnectException;
import com.dftc.mediadevice.data.exception.CameraDisconnectException;
import com.dftc.mediadevice.data.exception.NetworkConnectionException;
import com.dftc.mediadevice.data.exception.RtmpServerConnectException;
import com.dftc.onvif.Onvif;
import com.dftc.onvif.finder.CameraDevice;
import com.dftc.onvif.finder.HttpSoap;
import com.dftc.onvif.utils.Cache;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

import io.reactivex.Observable;

/**
 * {@link RestApi} implementation for retrieving data from the network.
 */
public class RestApiImpl implements RestApi {

    private static final String TAG = "RestApiImpl";
    private static final String DOWNLOAD_FILE_PATH = "download_cache";
    private static final int BUFFER_SIZE = 4 * 1024;
    private final Context context;
    private final Onvif mOnvif;

    /**
     * Constructor of the class
     *
     * @param context {@link Context}.
     */
    public RestApiImpl(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("The constructor parameters cannot be null!!!");
        }
        this.context = context.getApplicationContext();
        this.mOnvif = new Onvif();
    }

    @Override
    public Observable<List<CameraInfomation>> cameraInformationList(String name, String password) {
        return Observable.create(emitter -> {
            Log.d(TAG, "cameraInformationList");
            if (isThereInternetConnection()) {
                try {

                    List<CameraInfomation> list = new OnvifUtil()
                            .scanForCamera(new ControlMessage(name,
                                    password, 5));

                    // Add for test
//                    CameraInfomation a = new CameraInfomation();
//                    a.deviceAddr = "rtsp://192.168.2.67:8888/test";
//                    list.add(a);

                    if (list != null && !list.isEmpty()) {
                        emitter.onNext(list);
                        emitter.onComplete();
                    } else {
                        emitter.onError(new NetworkConnectionException());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    emitter.onError(new NetworkConnectionException(e.getCause()));
                }
            } else {
                emitter.onError(new NetworkConnectionException());
            }
        });
    }

    @Override
    public Observable<CameraDevice> cameraDevice(String cameraIP, int cameraPort, boolean mainRate) {
        return Observable.create(emitter -> {
            Log.d(TAG, "cameraDevice");
            if (isThereInternetConnection()) {
                try {

                    CameraDevice device = new HttpSoap().cameraDevice(cameraIP, cameraPort, mainRate);
                    if (device == null) {
                        emitter.onError(new NetworkConnectionException());
                        return;
                    }

                    boolean result = mOnvif.initCamStream(device.getId(), device.getRtspUrl());
                    if (!result) {
                        emitter.onError(new NetworkConnectionException());
                        return;
                    }
                    emitter.onNext(device);
                    emitter.onComplete();

                } catch (Exception e) {
                    e.printStackTrace();
                    emitter.onError(new NetworkConnectionException(e.getCause()));
                }
            } else {
                emitter.onError(new NetworkConnectionException());
            }
        });
    }

    @Override
    public Observable<Boolean> cameraDevice(CameraDevice device) {
        return Observable.create(emitter -> {
            Log.d(TAG, "cameraDevice");

            if (device != null) {
                synchronized (device) {
                    if (device != null) {
                        mOnvif.disconnectCam(device);
                    }
                }
            }
            emitter.onNext(true);
            emitter.onComplete();

        });
    }

    @Override
    public Observable<Integer> rtmpServer(String serAddr) {
        return Observable.create(emitter -> {
            Log.d(TAG, "rtmpServer");
            if (isThereInternetConnection()) {
                try {
                    Integer mSerId = mOnvif.connectRtmpSer(serAddr);
                    if (mSerId == -1) {
                        emitter.onError(new NetworkConnectionException());
                        return;
                    }
                    emitter.onNext(mSerId);
                    emitter.onComplete();

                } catch (Exception e) {
                    e.printStackTrace();
                    emitter.onError(new NetworkConnectionException(e.getCause()));
                }
            } else {
                emitter.onError(new NetworkConnectionException());
            }
        });
    }

    @Override
    public Observable<Boolean> rtmpServer(Integer serId) {
        return Observable.create(emitter -> {
            Log.d(TAG, "rtmpServer");

            boolean ret = false;
            synchronized (serId) {
                if (serId != -1) {
                    ret = mOnvif.disconnectRtmpSer(serId);
                }
            }
            emitter.onNext(ret);
            emitter.onComplete();

        });
    }

    @Override
    public Observable<Boolean> sendSpsPps(CameraDevice cameraDevice, Integer serId) {
        return Observable.create(emitter -> {
            Log.d(TAG, "sendSpsPps");
            try {
                if (cameraDevice == null) {
                    emitter.onError(new CameraDisconnectException());
                    return;
                }

                while (cameraDevice.isPushing()) {
                    if (!isThereInternetConnection()) {
                        emitter.onError(new NetworkConnectionException());
                        return;
                    }
                    byte[] h264 = null;
                    synchronized (cameraDevice) {
                        Log.d(TAG, "getH264Stream : " + cameraDevice.getId());
                        h264 = mOnvif.getH264Stream(cameraDevice);
                    }
                    if (h264 == null) {
                        Log.e(TAG, "h264 == null");
                        emitter.onError(new CameraConnectException());
                        return;
                    }
                    synchronized (serId) {
                        if (serId == -1) {
                            emitter.onError(new RtmpServerConnectException());
                            return;
                        }
                        if (mOnvif.sendSpsPps(serId, h264, cameraDevice)) {
                            emitter.onNext(true);
                            emitter.onComplete();
                            return;
                        }
                    }
                    emitter.onNext(false);
                }
                emitter.onError(new CameraDisconnectException());
            } catch (Exception e) {
                e.printStackTrace();
                emitter.onError(new NetworkConnectionException(e.getCause()));
            }

        });
    }

    @Override
    public Observable<Boolean> annexH264(CameraDevice cameraDevice, Integer serId) {
        return Observable.create(emitter -> {
            Log.d(TAG, "annexH264");
            try {
                if (cameraDevice == null) {
                    emitter.onError(new CameraDisconnectException());
                    return;
                }

                long start = -1;//System.currentTimeMillis();
                int tick = 0;

                while (cameraDevice.isPushing()) {
                    if (!isThereInternetConnection()) {
                        emitter.onError(new NetworkConnectionException());
                        return;
                    }
                    byte[] h264 = null;
                    synchronized (cameraDevice) {
                        Log.d(TAG, "getH264Stream : " + cameraDevice.getId());
                        h264 = mOnvif.getH264Stream(cameraDevice);
                    }
                    if (h264 == null) {
                        Log.e(TAG, "h264 == null");
                        emitter.onError(new CameraConnectException());
                        return;
                    }
                    boolean ret;
                    synchronized (serId) {
                        if (serId == -1) {
                            emitter.onError(new RtmpServerConnectException());
                            return;
                        }

                        //int tick = (int) (System.currentTimeMillis() - start);
                        if (start == -1)
                            start = System.currentTimeMillis();
                        int t = (int) (System.currentTimeMillis() - start);
                        if (t < tick) {
                            Thread.sleep(tick - t);
                        }
                        Log.d(TAG, "tick:" + tick);
                        ret = mOnvif.annexH264(serId, h264, tick);
                    }
                    if (ret) {
                        tick += 40;
                    }
                    if (!ret) {
                        Log.e(TAG, "annexH264 error!");
                        emitter.onError(new RtmpServerConnectException());
                        return;
                    }
                    emitter.onNext(true);
                }
                emitter.onError(new CameraDisconnectException());
            } catch (Exception e) {
                e.printStackTrace();
                emitter.onError(new NetworkConnectionException(e.getCause()));
            }

        });
    }

    @Override
    public Observable<File> screenshot(String snapshotUri) {
        return Observable.create(emitter -> {
            Log.d(TAG, "screenshot");
            Cache.createDir(DOWNLOAD_FILE_PATH);
            File file = new File(Cache.getRealFilePath(DOWNLOAD_FILE_PATH
                    + "/" + System.currentTimeMillis() + ".jpg"));

            URL url = null;
            try {
                url = new URL(snapshotUri);
            } catch (MalformedURLException e) {
                e.printStackTrace();
                emitter.onError(new NetworkConnectionException(e.getCause()));
                return;
            }
            URLConnection conn = null;
            try {
                conn = url.openConnection();
            } catch (IOException e) {
                emitter.onError(new NetworkConnectionException(e.getCause()));
                return;
            }
            long fileSize = conn.getContentLength();
            Log.d(TAG, "loadScreenshot fileSize:" + fileSize);
            if (fileSize <= 0) {
                Log.e(TAG, "loadScreenshot network disable");
                emitter.onError(new NetworkConnectionException());
                return;
            }
            long curPosition = 0;
            long endPosition = fileSize - 1;
            BufferedInputStream bis = null;
            RandomAccessFile fos = null;
            byte[] buf = new byte[BUFFER_SIZE];
            URLConnection con = null;
            try {
                con = url.openConnection();
                con.setAllowUserInteraction(true);
                con.setRequestProperty("Range", "bytes=0-" + endPosition);
                fos = new RandomAccessFile(file, "rw");
                fos.seek(0);
                bis = new BufferedInputStream(con.getInputStream());
                while (curPosition < endPosition) {
                    int len = bis.read(buf, 0, BUFFER_SIZE);
                    if (len == -1) {
                        break;
                    }
                    fos.write(buf, 0, len);
                    curPosition = curPosition + len;
                }
                emitter.onNext(file);
                emitter.onComplete();
            } catch (IOException e) {
                emitter.onError(new NetworkConnectionException(e.getCause()));
            } finally {
                try {
                    if (bis != null)
                        bis.close();
                    if (fos != null)
                        fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }


        });
    }

    /**
     * Checks if the device has any active internet connection.
     *
     * @return true device with internet connection, otherwise false.
     */

    private boolean isThereInternetConnection() {
        boolean isConnected;

        ConnectivityManager connectivityManager =
                (ConnectivityManager) this.context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
        isConnected = (networkInfo != null && networkInfo.isConnectedOrConnecting());

        return isConnected;
    }
}
