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
package com.dftc.mediadevice.domain.interactor;


import com.dftc.mediadevice.domain.executor.PostExecutionThread;
import com.dftc.mediadevice.domain.executor.ThreadExecutor;
import com.dftc.mediadevice.domain.repository.CameraRepository;
import com.dftc.onvif.finder.CameraDevice;

import javax.inject.Inject;

import dagger.internal.Preconditions;
import io.reactivex.Observable;

/**
 * This class is an implementation of {@link UseCase} that represents a use case for
 * retrieving data related to an specific {@link CameraDevice}.
 */
public class ConnectCameraDevice extends UseCase<CameraDevice, ConnectCameraDevice.Params> {

    private final CameraRepository userRepository;

    @Inject
    ConnectCameraDevice(CameraRepository userRepository, ThreadExecutor threadExecutor,
                        PostExecutionThread postExecutionThread) {
        super(threadExecutor, postExecutionThread);
        this.userRepository = userRepository;
    }

    @Override
    Observable<CameraDevice> buildUseCaseObservable(Params params) {
        Preconditions.checkNotNull(params);
        return this.userRepository.cameraDevice(params.cameraIP, params.cameraPort, params.mainRate);
    }

    public static final class Params {

        private final String cameraIP;
        private final Integer cameraPort;
        private final boolean mainRate;

        private Params(String cameraIP, Integer cameraPort, boolean mainRate) {
            this.cameraIP = cameraIP;
            this.cameraPort = cameraPort;
            this.mainRate = mainRate;
        }

        public static Params forUser(String cameraIP, Integer cameraPort, boolean mainRate) {
            return new Params(cameraIP, cameraPort, mainRate);
        }
    }
}
