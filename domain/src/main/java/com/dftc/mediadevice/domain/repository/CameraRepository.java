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
package com.dftc.mediadevice.domain.repository;

import android.graphics.Bitmap;

import com.dftc.mediadevice.domain.Camera;
import com.dftc.onvif.finder.CameraDevice;

import java.util.List;

import io.reactivex.Observable;


/**
 * Interface that represents a Repository for getting {@link Camera} related data.
 */
public interface CameraRepository {
    /**
     * Get an {@link Observable} which will emit a List of {@link Camera}.
     */
    Observable<List<Camera>> cameras(String name, String password);

    /**
     * Get an {@link Observable} which will emit a {@link CameraDevice}.
     *
     * @param cameraIP, cameraPort, mainRate The camera id used to retrieve camera data.
     */
    Observable<CameraDevice> cameraDevice(String cameraIP, Integer cameraPort, boolean mainRate);

    Observable<Boolean> cameraDevice(CameraDevice device);

    Observable<Integer> rtmpServer(String serAddr);

    Observable<Boolean> rtmpServer(Integer serId);

    Observable<Boolean> sendSpsPps(CameraDevice cameraDevice, Integer serId);

    Observable<Boolean> annexH264(CameraDevice cameraDevice, Integer serId);

    Observable<Bitmap> screenshot(String snapshotUri);
}
