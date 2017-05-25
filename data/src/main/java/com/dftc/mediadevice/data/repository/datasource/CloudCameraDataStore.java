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
package com.dftc.mediadevice.data.repository.datasource;


import com.dftc.libonvif.model.CameraInfomation;
import com.dftc.mediadevice.data.net.RestApi;
import com.dftc.onvif.finder.CameraDevice;

import java.io.File;
import java.util.List;

import io.reactivex.Observable;

/**
 * {@link CameraDataStore} implementation based on connections to the api (Cloud).
 */
class CloudCameraDataStore implements CameraDataStore {

    private final RestApi restApi;

    /**
     * Construct a {@link CameraDataStore} based on connections to the api (Cloud).
     *
     * @param restApi The {@link RestApi} implementation to use.
     */
    CloudCameraDataStore(RestApi restApi) {
        this.restApi = restApi;
    }

    @Override
    public Observable<List<CameraInfomation>> cameraInformationList(String name, String password) {
        return this.restApi.cameraInformationList(name, password);
    }

    @Override
    public Observable<CameraDevice> cameraDevice(String cameraIP, int cameraPort, boolean mainRate) {
        return this.restApi.cameraDevice(cameraIP, cameraPort, mainRate);
    }

    @Override
    public Observable<Boolean> cameraDevice(CameraDevice device) {
        return this.restApi.cameraDevice(device);
    }

    @Override
    public Observable<Integer> rtmpServer(String serAddr) {
        return this.restApi.rtmpServer(serAddr);
    }

    @Override
    public Observable<Boolean> rtmpServer(Integer serId) {
        return this.restApi.rtmpServer(serId);
    }

    @Override
    public Observable<Boolean> sendSpsPps(CameraDevice cameraDevice, Integer serId) {
        return this.restApi.sendSpsPps(cameraDevice, serId);
    }

    @Override
    public Observable<Boolean> annexH264(CameraDevice cameraDevice, Integer serId) {
        return this.restApi.annexH264(cameraDevice, serId);
    }

    @Override
    public Observable<File> screenshot(String snapshotUri) {
        return this.restApi.screenshot(snapshotUri);
    }
}
