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
package com.dftc.mediadevice.data.repository.datasource;

import android.content.Context;
import android.support.annotation.NonNull;

import com.dftc.mediadevice.data.net.RestApi;
import com.dftc.mediadevice.data.net.RestApiImpl;

import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Factory that creates different implementations of {@link CameraDataStore}.
 */
@Singleton
public class CameraDataStoreFactory {

  private final Context context;

  @Inject
  CameraDataStoreFactory(@NonNull Context context) {
    this.context = context.getApplicationContext();
  }

  /**
   * Create {@link CameraDataStore} to retrieve data from the Cloud.
   */
  public CameraDataStore createCloudDataStore() {
    final RestApi restApi = new RestApiImpl(this.context);

    return new CloudCameraDataStore(restApi);
  }
}
