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
package com.dftc.mediadevice.data.repository;

import android.graphics.Bitmap;

import com.dftc.mediadevice.data.mapper.CameraDataMapper;
import com.dftc.mediadevice.data.mapper.CameraScreenshotFileMapper;
import com.dftc.mediadevice.data.repository.datasource.CameraDataStore;
import com.dftc.mediadevice.data.repository.datasource.CameraDataStoreFactory;
import com.dftc.mediadevice.domain.Camera;
import com.dftc.mediadevice.domain.repository.CameraRepository;
import com.dftc.onvif.finder.CameraDevice;

import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

import io.reactivex.Observable;

/**
 * {@link CameraRepository} for retrieving camera data.
 */
@Singleton
public class CameraDataRepository implements CameraRepository {

    private final CameraDataStoreFactory cameraDataStoreFactory;
    private final CameraDataMapper cameraEntityDataMapper;
    private final CameraScreenshotFileMapper cameraScreenshotFileMapper;
    private final CameraDataStore cameraDataStore;

    /**
     * Constructs a {@link CameraRepository}.
     *
     * @param dataStoreFactory A factory to construct different data source implementations.
     * @param cameraEntityDataMapper {@link CameraDataMapper}.
     */
    @Inject
    CameraDataRepository(CameraDataStoreFactory dataStoreFactory,
                         CameraDataMapper cameraEntityDataMapper,
                         CameraScreenshotFileMapper cameraScreenshotFileMapper) {
        this.cameraDataStoreFactory = dataStoreFactory;
        this.cameraEntityDataMapper = cameraEntityDataMapper;
        this.cameraScreenshotFileMapper = cameraScreenshotFileMapper;
        this.cameraDataStore = this.cameraDataStoreFactory.createCloudDataStore();
    }

    @Override
    public Observable<List<Camera>> cameras(String name, String password) {
        //we always get all cameras from the cloud
        return cameraDataStore.cameraInformationList(name, password).map(this.cameraEntityDataMapper::transform);
    }

    /**
     * Get an {@link Observable} which will emit a {@link CameraDevice}.
     *
     * @param cameraIP
     * @param cameraPort
     * @param mainRate
     */
    @Override
    public Observable<CameraDevice> cameraDevice(String cameraIP, int cameraPort, boolean mainRate) {
        return cameraDataStore.cameraDevice(cameraIP, cameraPort, mainRate);
    }

    @Override
    public Observable<Boolean> cameraDevice(CameraDevice device) {
        return cameraDataStore.cameraDevice(device);
    }

    @Override
    public Observable<Integer> rtmpServer(String serAddr) {
        return cameraDataStore.rtmpServer(serAddr);
    }

    @Override
    public Observable<Boolean> rtmpServer(Integer serId) {
        return cameraDataStore.rtmpServer(serId);
    }

    @Override
    public Observable<Boolean> sendSpsPps(CameraDevice cameraDevice, Integer serId) {
        return cameraDataStore.sendSpsPps(cameraDevice, serId);
    }

    @Override
    public Observable<Boolean> annexH264(CameraDevice cameraDevice, Integer serId) {
        return cameraDataStore.annexH264(cameraDevice, serId);
    }

    @Override
    public Observable<Bitmap> screenshot(String snapshotUri) {
        return cameraDataStore.screenshot(snapshotUri).map(this.cameraScreenshotFileMapper::transform);
    }
}
