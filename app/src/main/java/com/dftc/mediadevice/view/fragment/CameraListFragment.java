/**
 * Copyright (C) 2014 android10.org. All rights reserved.
 *
 * @author Fernando Cejas (the android10 coder)
 */
package com.dftc.mediadevice.view.fragment;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v7.widget.RecyclerView;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.view.animation.LinearInterpolator;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.dftc.baseview.CustomDialog;
import com.dftc.baseview.CustomEditText;
import com.dftc.mediadevice.R;
import com.dftc.mediadevice.internal.di.components.CameraComponent;
import com.dftc.mediadevice.model.CameraModel;
import com.dftc.mediadevice.presenter.CameraListPresenter;
import com.dftc.mediadevice.view.CameraListView;
import com.dftc.mediadevice.view.adapter.CamerasAdapter;
import com.dftc.mediadevice.view.adapter.CamerasLayoutManager;

import java.util.Collection;

import javax.inject.Inject;

import butterknife.Bind;
import butterknife.ButterKnife;
import butterknife.OnClick;

/**
 * Fragment that shows a list of Users.
 */
public class CameraListFragment extends BaseFragment implements CameraListView {

    @Inject
    CameraListPresenter cameraListPresenter;
    @Inject
    CamerasAdapter camerasAdapter;

    @Bind(R.id.rv_camera)
    RecyclerView rv_camera;
    @Bind(R.id.et_rtmp_url)
    EditText et_rtmp_url;
    @Bind(R.id.bt_connectRtmpSer)
    Button bt_connectRtmpSer;
    @Bind(R.id.bt_disconnectRtmpSer)
    Button bt_disconnectRtmpSer;
    @Bind(R.id.bt_annexH264)
    Button bt_annexH264;
    @Bind(R.id.bt_stopAnnexH264)
    Button bt_stopAnnexH264;
    @Bind(R.id.wait_layout)
    LinearLayout wait_layout;
    @Bind(R.id.waitTextView)
    TextView waitTextView;
    @Bind(R.id.loadAnimation)
    ImageView loadAnimation;
    @Bind(R.id.waitButton)
    Button waitButton;

    private Animation mAnimation;

    public CameraListFragment() {
        setRetainInstance(true);
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.getComponent(CameraComponent.class).inject(this);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        final View fragmentView = inflater.inflate(R.layout.fragment_camera_list, container, false);
        ButterKnife.bind(this, fragmentView);
        initView();
        setupRecyclerView();
        return fragmentView;
    }

    private void initView() {
        bt_disconnectRtmpSer.setVisibility(View.GONE);
        bt_stopAnnexH264.setVisibility(View.GONE);
        bt_annexH264.setEnabled(false);

        mAnimation = AnimationUtils.loadAnimation(context(), R.anim.rotate); // 旋转动画
        mAnimation.setInterpolator(new LinearInterpolator());
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        this.cameraListPresenter.setView(this);
        if (savedInstanceState == null) {
            this.loadCameraList();
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        this.cameraListPresenter.resume();
    }

    @Override
    public void onPause() {
        super.onPause();
        this.cameraListPresenter.pause();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        rv_camera.setAdapter(null);
        ButterKnife.unbind(this);
    }

    @Override
    public void onDestroy() {
        this.cameraListPresenter.destroy();
        super.onDestroy();
    }

    @Override
    public void onDetach() {
        super.onDetach();
    }

    @Override
    public void showLoading() {
        waitTextView.setText("正在搜索摄像头");
        loadAnimation.setBackgroundResource(R.drawable.loading_gif);
        loadAnimation.startAnimation(mAnimation); // 初始化动画

        rv_camera.setVisibility(View.GONE);
        wait_layout.setVisibility(View.VISIBLE);
        loadAnimation.setVisibility(View.VISIBLE);
        this.getActivity().setProgressBarIndeterminateVisibility(true);
    }

    @Override
    public void hideLoading() {
        loadAnimation.clearAnimation();
        wait_layout.setVisibility(View.GONE);
        rv_camera.setVisibility(View.VISIBLE);
    }

    @Override
    public void showRetry() {
        waitTextView.setText("没有搜索到摄像头");

        loadAnimation.clearAnimation();
        loadAnimation.setBackgroundResource(R.drawable.icon_cry);
        wait_layout.setVisibility(View.VISIBLE);
        waitButton.setVisibility(View.VISIBLE);
    }

    @Override
    public void hideRetry() {
        waitButton.setVisibility(View.GONE);
    }

    @Override
    public void renderUserList(Collection<CameraModel> cameraModelCollection) {
        if (cameraModelCollection != null) {
            this.camerasAdapter.setUsersCollection(cameraModelCollection);
        }
    }

    @Override
    public void viewCamera(CameraModel cameraModel) {
        this.camerasAdapter.notifyDataSetChanged();
    }

    @Override
    public void onConnectRtmpServerStart() {
        bt_connectRtmpSer.setEnabled(false);
        bt_connectRtmpSer.setText("正在连接RTMP服务器...");
    }

    @Override
    public void onConnectRtmpServerError() {
        bt_connectRtmpSer.setEnabled(true);
        bt_connectRtmpSer.setText("连接RTMP服务器");
        showToastMessage("网络连接出错");
    }

    @Override
    public void onConnectRtmpServerComplete() {
        bt_connectRtmpSer.setText("已连接RTMP服务器");
        bt_connectRtmpSer.setVisibility(View.GONE);
        bt_disconnectRtmpSer.setVisibility(View.VISIBLE);
    }

    @Override
    public void onDisconnectRtmpServer() {
        bt_annexH264.setText("开始推流");
        bt_annexH264.setVisibility(View.VISIBLE);
        bt_annexH264.setEnabled(false);
        bt_stopAnnexH264.setVisibility(View.GONE);
        bt_connectRtmpSer.setText("连接RTMP服务器");
        bt_connectRtmpSer.setVisibility(View.VISIBLE);
        bt_connectRtmpSer.setEnabled(true);
        bt_disconnectRtmpSer.setVisibility(View.GONE);
    }

    @Override
    public void onAnnexH264ButtonEnabled() {
        bt_annexH264.setEnabled(true);
    }

    @Override
    public void onAnnexH264Start() {
        bt_annexH264.setEnabled(false);
        bt_annexH264.setText("正在推流...");
        bt_annexH264.setVisibility(View.GONE);
        bt_stopAnnexH264.setVisibility(View.VISIBLE);
    }

    @Override
    public void onAnnexH264Error() {
        //bt_annexH264.setEnabled(true);
        bt_annexH264.setText("开始推流");
        bt_annexH264.setVisibility(View.VISIBLE);
        bt_stopAnnexH264.setVisibility(View.GONE);
    }

    @Override
    public void showError(String message) {
        this.showToastMessage(message);
    }

    @Override
    public Context context() {
        return this.getActivity().getApplicationContext();
    }

    private void setupRecyclerView() {
        this.camerasAdapter.setOnItemClickListener(onItemClickListener);
        this.rv_camera.setLayoutManager(new CamerasLayoutManager(context()));
        this.rv_camera.setAdapter(camerasAdapter);
        this.rv_camera.setFocusable(true);
        this.rv_camera.setFocusableInTouchMode(true);
    }

    /**
     * Loads all cameras.
     */
    private void loadCameraList() {
        this.cameraListPresenter.initialize();
    }

    private CamerasAdapter.OnItemClickListener onItemClickListener =
            new CamerasAdapter.OnItemClickListener() {
                @Override
                public void onUserItemClicked(CameraModel cameraModel) {
                    if (CameraListFragment.this.cameraListPresenter != null && cameraModel != null) {
                        CameraListFragment.this.cameraListPresenter.onCameraClicked(cameraModel);
                    }
                }
            };

    @OnClick(R.id.waitButton)
    void onButtonRetryClick() {
        CameraListFragment.this.loadCameraList();
    }

    @OnClick(R.id.bt_connectRtmpSer)
    void onButtonConnectRtmpSerClick() {
        this.cameraListPresenter.onButtonConnectRtmpSerClick(et_rtmp_url.getText().toString());
    }

    @OnClick(R.id.bt_disconnectRtmpSer)
    void onButtonDisconnectRtmpSerClick() {
        this.cameraListPresenter.onButtonDisconnectRtmpSerClick();
    }

    @OnClick(R.id.bt_annexH264)
    void onButtonAnnexH264Click() {
        this.cameraListPresenter.onButtonAnnexH264Click();
    }

    @OnClick(R.id.bt_stopAnnexH264)
    void onButtonStopAnnexH264Click() {
        this.cameraListPresenter.onButtonStopAnnexH264Click();
    }

    public void onButtonAddCameraClick() {
        this.cameraListPresenter.onButtonAddCameraClick();
    }

    public void onButtonShowRtspClick() {
        this.cameraListPresenter.onButtonShowRtspClick();
    }

    public void onButtonShowRtmpClick() {
        this.cameraListPresenter.onButtonShowRtmpClick();
    }

    @Override
    public void showAddCameraDialog(String ipAddr, String port) {
        CustomDialog.Builder builder = new CustomDialog.Builder(getActivity());

        builder.setTitle(R.string.dialog_add_camera);

        LinearLayout fragment = (LinearLayout) getActivity().getLayoutInflater()
                .inflate(R.layout.fragment_camera_list_dialog_add_camera, null);
        builder.setContentView(fragment);

        final CustomEditText et_ip_addr = (CustomEditText) fragment.findViewById(R.id.et_ip_addr);
        final CustomEditText et_ip_port = (CustomEditText) fragment.findViewById(R.id.et_ip_port);
        et_ip_addr.setText(ipAddr);
        et_ip_port.setText(port);

        builder.setPositiveButton(R.string.ok,
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        String str_ip_addr = et_ip_addr.getText().toString();
                        String str_ip_port = et_ip_port.getText().toString();
                        if (TextUtils.isEmpty(str_ip_addr)) {
                            et_ip_addr.showPopupPrompt(R.string.input_empty);
                            return;
                        }
                        if (TextUtils.isEmpty(str_ip_port)) {
                            et_ip_port.showPopupPrompt(R.string.input_empty);
                            return;
                        }
                        CameraListFragment.this.cameraListPresenter.onAddCamera(
                                str_ip_addr,
                                str_ip_port
                        );
                        dialog.cancel();

                    }
                });
        builder.setNegativeButton(R.string.cancel, null);
        builder.create().show();
    }
}
