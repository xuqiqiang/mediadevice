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
package com.dftc.mediadevice.presenter;

import android.support.annotation.NonNull;
import android.util.Log;

import com.dftc.mediadevice.data.cache.Cache;
import com.dftc.mediadevice.data.cache.SharedPreferencesKey;
import com.dftc.mediadevice.internal.di.PerActivity;
import com.dftc.mediadevice.view.SettingsView;

import javax.inject.Inject;

/**
 * {@link Presenter} that controls communication between views and models of the presentation
 * layer.
 */
@PerActivity
public class SettingsPresenter implements Presenter {

    private SettingsView settingsView;

    @Inject
    public SettingsPresenter() {

    }

    public void setView(@NonNull SettingsView view) {
        this.settingsView = view;
    }

    @Override
    public void resume() {
    }

    @Override
    public void pause() {
    }

    @Override
    public void destroy() {
        this.settingsView = null;
    }

    public void onSetAccount(String name, String password) {

        Log.d("SettingsPresenter", "name:" + name + ",password:" + password);
        Cache.writeString(
                SharedPreferencesKey.KEY_ACCOUNT_NAME,
                name);
        Cache.writeString(
                SharedPreferencesKey.KEY_ACCOUNT_PASSWORD,
                password);
    }

    public void onButtonAccountClick() {
        settingsView.showAccountDialog(
                Cache.readString(
                        SharedPreferencesKey.KEY_ACCOUNT_NAME,
                        SharedPreferencesKey.KEY_ACCOUNT_NAME_DEFAULT),
                Cache.readString(
                        SharedPreferencesKey.KEY_ACCOUNT_PASSWORD,
                        SharedPreferencesKey.KEY_ACCOUNT_PASSWORD_DEFAULT));
    }

    public void onSetMainRate(boolean value) {
        Log.d("SettingsPresenter", "onMainRate:" + value);
        Cache.writeBoolean(SharedPreferencesKey.KEY_MAIN_RATE, value);
    }

    public boolean isMainRate() {
        return Cache.readBoolean(SharedPreferencesKey.KEY_MAIN_RATE,
                SharedPreferencesKey.KEY_MAIN_RATE_DEFAULT);
    }

}
