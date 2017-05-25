package com.dftc.mediadevice.view.activity;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.design.widget.NavigationView;
import android.support.v4.view.GravityCompat;
import android.support.v4.widget.DrawerLayout;
import android.support.v7.app.ActionBarDrawerToggle;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;

import com.dftc.mediadevice.R;
import com.dftc.mediadevice.internal.di.HasComponent;
import com.dftc.mediadevice.internal.di.components.CameraComponent;
import com.dftc.mediadevice.internal.di.components.DaggerCameraComponent;
import com.dftc.mediadevice.view.fragment.CameraListFragment;

import butterknife.Bind;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class MainActivity extends BaseActivity
        implements HasComponent<CameraComponent>, NavigationView.OnNavigationItemSelectedListener {

    @Bind(R.id.toolbar)
    Toolbar toolbar;

    @Bind(R.id.drawer_layout)
    DrawerLayout drawer;

    @Bind(R.id.nav_view)
    NavigationView navigationView;

    private CameraListFragment mCameraListFragment;

    private CameraComponent cameraComponent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.bind(this);
        initView();

        initializeInjector();
        if (savedInstanceState == null) {
            mCameraListFragment = new CameraListFragment();
            addFragment(R.id.fragmentContainer, mCameraListFragment);
        }
    }

    void initView() {
        setSupportActionBar(toolbar);
        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.setDrawerListener(toggle);
        toggle.syncState();

        navigationView.getHeaderView(0)
                .setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        Uri uri = Uri
                                .parse("https://xuqiqiang.github.io");
                        Intent it = new Intent(Intent.ACTION_VIEW, uri);
                        startActivity(it);
                    }
                });
        navigationView.setNavigationItemSelectedListener(this);
    }

    @OnClick(R.id.fab_add_camera)
    void onButtonAddCameraClick() {
        this.mCameraListFragment.onButtonAddCameraClick();
    }

    void navigateToSettings() {
        this.navigator.navigateToSettings(this);
    }

    @Override
    public void onBackPressed() {
        if (drawer.isDrawerOpen(GravityCompat.START)) {
            drawer.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_show_rtsp) {
            this.mCameraListFragment.onButtonShowRtspClick();
            return true;
        } else if (id == R.id.action_show_rtmp) {
            this.mCameraListFragment.onButtonShowRtmpClick();
            return true;
        } else if (id == R.id.action_settings) {
            this.navigateToSettings();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @SuppressWarnings("StatementWithEmptyBody")
    @Override
    public boolean onNavigationItemSelected(MenuItem item) {
        // Handle navigation view item clicks here.
        int id = item.getItemId();
        if (id == R.id.nav_add) {
            this.onButtonAddCameraClick();
        } else if (id == R.id.nav_show_rtsp) {
            this.mCameraListFragment.onButtonShowRtspClick();
        } else if (id == R.id.nav_show_rtmp) {
            this.mCameraListFragment.onButtonShowRtmpClick();
        } else if (id == R.id.nav_manage) {
            this.navigateToSettings();
        } else if (id == R.id.nav_share) {

        } else if (id == R.id.nav_send) {

        }

        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
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
