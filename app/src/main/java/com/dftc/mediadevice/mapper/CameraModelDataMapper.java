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

import com.dftc.mediadevice.domain.Camera;
import com.dftc.mediadevice.internal.di.PerActivity;
import com.dftc.mediadevice.model.CameraModel;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import javax.inject.Inject;

/**
 * Mapper class used to transform {@link Camera} (in the domain layer) to {@link CameraModel} in the
 * presentation layer.
 */
@PerActivity
public class CameraModelDataMapper {

    @Inject
    public CameraModelDataMapper() {
    }

    /**
     * Transform a {@link Camera} into an {@link CameraModel}.
     *
     * @param camera Object to be transformed.
     * @return {@link CameraModel}.
     */
    public CameraModel transform(Camera camera) {
        if (camera == null) {
            throw new IllegalArgumentException("Cannot transform a null value");
        }
        final CameraModel cameraModel = new CameraModel(camera.getIP(), camera.getPort(), camera.getUUID());
        cameraModel.setStatus(camera.getStatus());

        return cameraModel;
    }

    /**
     * Transform a Collection of {@link Camera} into a Collection of {@link CameraModel}.
     *
     * @param camerasCollection Objects to be transformed.
     * @return List of {@link CameraModel}.
     */
    public Collection<CameraModel> transform(Collection<Camera> camerasCollection) {
        Collection<CameraModel> cameraModelsCollection;

        if (camerasCollection != null && !camerasCollection.isEmpty()) {
            cameraModelsCollection = new ArrayList<>();
            for (Camera camera : camerasCollection) {
                cameraModelsCollection.add(transform(camera));
            }
        } else {
            cameraModelsCollection = Collections.emptyList();
        }

        return cameraModelsCollection;
    }
}
