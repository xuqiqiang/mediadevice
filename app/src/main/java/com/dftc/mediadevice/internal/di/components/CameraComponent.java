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
package com.dftc.mediadevice.internal.di.components;

import com.dftc.mediadevice.internal.di.PerActivity;
import com.dftc.mediadevice.internal.di.modules.ActivityModule;
import com.dftc.mediadevice.internal.di.modules.CameraModule;
import com.dftc.mediadevice.view.fragment.CameraListFragment;
import com.dftc.mediadevice.view.fragment.SettingsFragment;

import dagger.Component;

/**
 * A scope {@link com.dftc.mediadevice.internal.di.PerActivity} component.
 * Injects user specific Fragments.
 */
@PerActivity
@Component(dependencies = ApplicationComponent.class, modules = {ActivityModule.class, CameraModule.class})
public interface CameraComponent extends ActivityComponent {
    void inject(CameraListFragment userListFragment);
    void inject(SettingsFragment settingsFragment);
}
