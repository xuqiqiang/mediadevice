/**
 * Copyright (C) 2015 Fernando Cejas Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dftc.mediadevice.data.net;

import com.dftc.libonvif.model.CameraInfomation;
import com.dftc.onvif.finder.CameraDevice;

import java.io.File;
import java.util.List;

import io.reactivex.Observable;

/**
 * RestApi for retrieving data from the network.
 */
public interface RestApi {

  /**
   * Retrieves an {@link Observable} which will emit a List of {@link CameraInfomation}.
   */
  Observable<List<CameraInfomation>> cameraInformationList(String name, String password);

  /**
   * Retrieves an {@link Observable} which will emit a {@link CameraDevice}.
   *
   * @param cameraIP, cameraPort, mainRate The user id used to get camera device data.
   */
  Observable<CameraDevice> cameraDevice(String cameraIP, int cameraPort, boolean mainRate);

  Observable<Boolean> cameraDevice(CameraDevice device);

  Observable<Integer> rtmpServer(String serAddr);

  Observable<Boolean> rtmpServer(Integer serId);

  Observable<Boolean> sendSpsPps(CameraDevice cameraDevice, Integer serId);

  Observable<Boolean> annexH264(CameraDevice cameraDevice, Integer serId);

  Observable<File> screenshot(String snapshotUri);
}
