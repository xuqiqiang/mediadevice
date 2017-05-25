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
package com.dftc.mediadevice.model;

import android.graphics.Bitmap;

/**
 * Class that represents a user in the presentation layer.
 */
public class CameraModel {

    private String mIP;
    private int mPort;
    private String mUUID;

    private Bitmap screenshot;

    public static final int STATUS_DISCONNECT = 0, STATUS_CONNECTING = 1, STATUS_CONNECTED = 2;
    private int mStatus = STATUS_DISCONNECT;

    public CameraModel(String ip, int port, String uuid) {
        mIP = ip;
        mPort = port;
        mUUID = uuid;
    }

    public String getIP() {
        return mIP;
    }

    public int getPort() {
        return mPort;
    }

    public String getUUID() {
        return mUUID;
    }

    public void setStatus(int status) {
        mStatus = status;
    }

    public int getStatus() {
        return mStatus;
    }

    public void setScreenshot(Bitmap screenshot) {
        this.screenshot = screenshot;
    }

    public Bitmap getScreenshot() {
        return this.screenshot;
    }

    @Override
    public boolean equals(Object c) {
        return c != null &&
                c instanceof CameraModel &&
                this.mIP == ((CameraModel) c).mIP &&
                this.mPort == ((CameraModel) c).mPort &&
                this.mUUID == ((CameraModel) c).mUUID;
    }

    @Override
    public String toString() {
        return "Camera{" +
                "ip='" + mIP + '\'' +
                ", port='" + mPort + '\'' +
                ", UUID='" + mUUID + '\'' +
                '}';
    }
}
