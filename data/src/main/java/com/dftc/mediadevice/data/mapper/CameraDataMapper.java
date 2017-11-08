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
package com.dftc.mediadevice.data.mapper;

import android.text.TextUtils;

import com.dftc.libonvif.model.CameraInfomation;
import com.dftc.mediadevice.data.exception.NetworkConnectionException;
import com.dftc.mediadevice.domain.Camera;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Mapper class used to transform {@link CameraInfomation} (in the data layer) to {@link Camera} in the
 * domain layer.
 */
@Singleton
public class CameraDataMapper {

    private static final String TAG_START = "://";
    private static final String TAG_END = "/";
    private static final String TAG_PORT = ":";

    @Inject
    CameraDataMapper() {
    }

    /**
     * Transform a {@link CameraInfomation} into an {@link Camera}.
     *
     * @param ai Object to be transformed.
     * @return {@link Camera} if valid {@link CameraInfomation} otherwise null.
     */
    public Camera transform(CameraInfomation ai) {
        Camera camera = null;
        if (ai != null && !TextUtils.isEmpty(ai.deviceAddr)) {

            try {
                int ip_start = ai.deviceAddr.indexOf(TAG_START);
                if (ip_start == -1)
                    return null;

                ip_start += TAG_START.length();
                int ip_end = ai.deviceAddr.indexOf(TAG_END, ip_start);
                if (ip_end == -1)
                    ip_end = ai.deviceAddr.length();

                String ipAddr = ai.deviceAddr.substring(ip_start, ip_end);

                int port_start = ipAddr.indexOf(TAG_PORT);
                Integer port = null;
                if (port_start != -1) {
                    try {
                        port = Integer.parseInt(ipAddr.substring(port_start + TAG_PORT.length()));
                    } catch (NumberFormatException e) {
                        port = 8888;
                        e.printStackTrace();
                    }
                    ipAddr = ipAddr.substring(0, port_start);
                }
                camera = new Camera(ipAddr, port, UUID.randomUUID().toString());
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        return camera;
    }

    /**
     * Transform a List of {@link CameraInfomation} into a Collection of {@link Camera}.
     *
     * @param cameraInfomationCollection Object Collection to be transformed.
     * @return {@link Camera} if valid {@link CameraInfomation} otherwise null.
     */
    public List<Camera> transform(Collection<CameraInfomation> cameraInfomationCollection) throws NetworkConnectionException {
        final List<Camera> cameraList = new ArrayList<>();
        for (CameraInfomation cameraInfomation : cameraInfomationCollection) {
            final Camera camera = transform(cameraInfomation);
            if (camera != null) {
                cameraList.add(camera);
            }
        }
        if (cameraList.isEmpty())
            throw new NetworkConnectionException();
        return cameraList;
    }
}
