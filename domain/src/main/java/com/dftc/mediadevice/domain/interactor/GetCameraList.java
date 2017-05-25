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


import com.dftc.mediadevice.domain.Camera;
import com.dftc.mediadevice.domain.executor.PostExecutionThread;
import com.dftc.mediadevice.domain.executor.ThreadExecutor;
import com.dftc.mediadevice.domain.repository.CameraRepository;

import java.util.List;

import javax.inject.Inject;

import io.reactivex.Observable;

/**
 * This class is an implementation of {@link UseCase} that represents a use case for
 * retrieving a collection of all {@link Camera}.
 */
public class GetCameraList extends UseCase<List<Camera>, GetCameraList.Params> {

    private final CameraRepository cameraRepository;

    @Inject
    GetCameraList(CameraRepository cameraRepository, ThreadExecutor threadExecutor,
                  PostExecutionThread postExecutionThread) {
        super(threadExecutor, postExecutionThread);
        this.cameraRepository = cameraRepository;
    }

    @Override
    Observable<List<Camera>> buildUseCaseObservable(Params params) {
        return this.cameraRepository.cameras(params.name, params.password);
    }

    public static final class Params {

        private final String name;
        private final String password;

        private Params(String name, String password) {
            this.name = name;
            this.password = password;
        }

        public static Params forUser(String name, String password) {
            return new Params(name, password);
        }
    }
}
