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
package com.dftc.mediadevice.mapper;

import com.dftc.libonvif.model.CameraInfomation;
import com.dftc.mediadevice.domain.Camera;
import com.dftc.mediadevice.internal.di.PerActivity;

import javax.inject.Inject;

/**
 * Mapper class used to transform {@link CameraInfomation} (in the data layer) to {@link Camera} in the
 * domain layer.
 */
@PerActivity
public class RtmpServUrlMapper {

    @Inject
    RtmpServUrlMapper() {
    }

    public String transform(String rtmpServUrl) {
        if (rtmpServUrl == null)
            return null;

        String vhost = "?vhost=";
        int vhost_index = rtmpServUrl.indexOf(vhost);
        if (vhost_index == -1)
            return rtmpServUrl;

        String rtmpUrl = "rtmp://";
        rtmpUrl += rtmpServUrl.substring(vhost_index + vhost.length(), rtmpServUrl.length());

        String alivecdn = "rtmp://video-center.alivecdn.com/";
        int appName_end_index = rtmpServUrl.indexOf("/", alivecdn.length());
        rtmpUrl += "/" + rtmpServUrl.substring(alivecdn.length(), appName_end_index);

        rtmpUrl += rtmpServUrl.substring(appName_end_index, vhost_index);
        return rtmpUrl;
    }

}
