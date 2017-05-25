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


import android.graphics.Bitmap;

import com.dftc.mediadevice.domain.Camera;
import com.dftc.mediadevice.domain.executor.PostExecutionThread;
import com.dftc.mediadevice.domain.executor.ThreadExecutor;
import com.dftc.mediadevice.domain.repository.CameraRepository;

import javax.inject.Inject;

import io.reactivex.Observable;

/**
 * This class is an implementation of {@link UseCase} that represents a use case for
 * retrieving a collection of all {@link Camera}.
 */
public class GetCameraSrceenshot extends UseCase<Bitmap, GetCameraSrceenshot.Params> {

    private final CameraRepository cameraRepository;

    @Inject
    GetCameraSrceenshot(CameraRepository cameraRepository, ThreadExecutor threadExecutor,
                        PostExecutionThread postExecutionThread) {
        super(threadExecutor, postExecutionThread);
        this.cameraRepository = cameraRepository;
    }

    @Override
    Observable<Bitmap> buildUseCaseObservable(Params params) {
        return this.cameraRepository.screenshot(params.snapshotUri);
    }

    public static final class Params {

        private final String snapshotUri;

        private Params(String snapshotUri) {
            this.snapshotUri = snapshotUri;
        }

        public static Params forUser(String snapshotUri) {
            return new Params(snapshotUri);
        }
    }
}
