/**
 * Copyright (C) 2014 android10.org. All rights reserved.
 *
 * @author Fernando Cejas (the android10 coder)
 */
package com.dftc.mediadevice.view.activity;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.widget.Toolbar;

import com.dftc.mediadevice.R;
import com.dftc.mediadevice.internal.di.HasComponent;
import com.dftc.mediadevice.internal.di.components.CameraComponent;
import com.dftc.mediadevice.internal.di.components.DaggerCameraComponent;
import com.dftc.mediadevice.view.fragment.SettingsFragment;

import butterknife.Bind;
import butterknife.ButterKnife;


/**
 * Activity that shows a list of Users.
 */
public class SettingsActivity extends BaseActivity implements HasComponent<CameraComponent> {

    @Bind(R.id.toolbar)
    Toolbar toolbar;

    private CameraComponent cameraComponent;

    public static Intent getCallingIntent(Context context) {
        return new Intent(context, SettingsActivity.class);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.content_main);
        ButterKnife.bind(this);
        setSupportActionBar(toolbar);

        this.initializeInjector();
        if (savedInstanceState == null) {
            addFragment(R.id.fragmentContainer, new SettingsFragment());
        }
    }

    private void initializeInjector() {
        this.cameraComponent = DaggerCameraComponent.builder()
                .applicationComponent(getApplicationComponent())
                .activityModule(getActivityModule())
                .build();
    }

    @Override
    public CameraComponent getComponent() {
        return cameraComponent;
    }

}
