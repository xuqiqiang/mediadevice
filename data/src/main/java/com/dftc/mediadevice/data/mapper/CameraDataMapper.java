/**
 * Copyright (C) 2015 Fernando Cejas Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dftc.mediadevice.data.mapper;

import com.dftc.libonvif.model.CameraInfomation;
import com.dftc.mediadevice.domain.Camera;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Mapper class used to transform {@link CameraInfomation} (in the data layer) to {@link Camera} in the
 * domain layer.
 */
@Singleton
public class CameraDataMapper {

  @Inject
  CameraDataMapper() {}

  /**
   * Transform a {@link CameraInfomation} into an {@link Camera}.
   *
   * @param ai Object to be transformed.
   * @return {@link Camera} if valid {@link CameraInfomation} otherwise null.
   */
  public Camera transform(CameraInfomation ai) {
    Camera camera = null;
    if (ai != null) {

      int i, XAddrs_len = ai.deviceAddr.length();
      int ip_start = -1, ip_end = -1;
      int port_start = -1, port_end = -1;
      for (i = 0; i < XAddrs_len; i++) {
        if (ai.deviceAddr.charAt(i) == ':') {
          if (ip_start == -1)
            ip_start = i + 3;
          else {
            ip_end = i;
            port_start = i + 1;
          }

        } else if (ai.deviceAddr.charAt(i) == '/') {
          if (port_start != -1) {
            port_end = i;
            break;
          }

        }
      }

      int port = 8888;
      try {
        port = Integer.parseInt(ai.deviceAddr.substring(port_start, port_end));
      } catch (NumberFormatException e) {
        e.printStackTrace();
      }

      camera = new Camera(ai.deviceAddr.substring(ip_start, ip_end),
              port, null);
    }
    return camera;
  }

  /**
   * Transform a List of {@link CameraInfomation} into a Collection of {@link Camera}.
   *
   * @param cameraInfomationCollection Object Collection to be transformed.
   * @return {@link Camera} if valid {@link CameraInfomation} otherwise null.
   */
  public List<Camera> transform(Collection<CameraInfomation> cameraInfomationCollection) {
    final List<Camera> cameraList = new ArrayList<>();
    for (CameraInfomation cameraInfomation : cameraInfomationCollection) {
      final Camera camera = transform(cameraInfomation);
      if (camera != null) {
        cameraList.add(camera);
      }
    }
    return cameraList;
  }
}
