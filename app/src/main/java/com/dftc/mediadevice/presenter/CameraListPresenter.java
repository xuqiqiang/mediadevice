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

import android.graphics.Bitmap;
import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.util.Log;

import com.dftc.mediadevice.data.cache.Cache;
import com.dftc.mediadevice.data.cache.SharedPreferencesKey;
import com.dftc.mediadevice.domain.Camera;
import com.dftc.mediadevice.domain.exception.DefaultErrorBundle;
import com.dftc.mediadevice.domain.exception.ErrorBundle;
import com.dftc.mediadevice.domain.interactor.AnnexH264;
import com.dftc.mediadevice.domain.interactor.ConnectCameraDevice;
import com.dftc.mediadevice.domain.interactor.ConnectRtmpServer;
import com.dftc.mediadevice.domain.interactor.DefaultObserver;
import com.dftc.mediadevice.domain.interactor.DisconnectCameraDevice;
import com.dftc.mediadevice.domain.interactor.DisconnectRtmpServer;
import com.dftc.mediadevice.domain.interactor.GetCameraList;
import com.dftc.mediadevice.domain.interactor.GetCameraSrceenshot;
import com.dftc.mediadevice.domain.interactor.SendSpsPps;
import com.dftc.mediadevice.exception.ErrorMessageFactory;
import com.dftc.mediadevice.internal.di.PerActivity;
import com.dftc.mediadevice.mapper.CameraModelDataMapper;
import com.dftc.mediadevice.mapper.RtmpServUrlMapper;
import com.dftc.mediadevice.model.CameraModel;
import com.dftc.mediadevice.view.CameraListView;
import com.dftc.mediadevice.view.fragment.BaseFragment;
import com.dftc.mediadevice.view.fragment.CameraListFragment;
import com.dftc.onvif.finder.CameraDevice;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.inject.Inject;

import tv.danmaku.ijk.media.demo.activities.VideoActivity;

import static com.dftc.mediadevice.data.cache.Cache.readString;

/**
 * {@link Presenter} that controls communication between views and models of the presentation
 * layer.
 */
@PerActivity
public class CameraListPresenter implements Presenter {

    private final static String TAG = "CameraListPresenter";
    private final GetCameraList getCameraListUseCase;
    private final ConnectCameraDevice connectCameraDeviceUseCase;
    private final DisconnectCameraDevice disconnectCameraDeviceUseCase;
    private final ConnectRtmpServer connectRtmpServerUseCase;
    private final DisconnectRtmpServer disconnectRtmpServerUseCase;
    private final SendSpsPps sendSpsPpsUseCase;
    private final AnnexH264 annexH264UseCase;
    private final GetCameraSrceenshot getCameraSrceenshotUseCase;
    private final CameraModelDataMapper cameraModelDataMapper;
    private final RtmpServUrlMapper rtmpServUrlMapper;
    private CameraListView viewListView;
    private CameraModel mSelectCamera;
    private CameraDevice mCameraDevice;
    private Integer mSerId = -1;
    private String rtmpServUrl;

    private Collection<CameraModel> cameraModelsCollection;

    @Inject
    public CameraListPresenter(GetCameraList getUserListUserCase,
                               ConnectCameraDevice connectCameraDeviceUseCase,
                               DisconnectCameraDevice disconnectCameraDeviceUseCase,
                               ConnectRtmpServer connectRtmpServerUseCase,
                               DisconnectRtmpServer disconnectRtmpServerUseCase,
                               SendSpsPps sendSpsPpsUseCase,
                               AnnexH264 annexH264UseCase,
                               GetCameraSrceenshot getCameraSrceenshotUseCase,
                               CameraModelDataMapper cameraModelDataMapper,
                               RtmpServUrlMapper rtmpServUrlMapper) {
        this.getCameraListUseCase = getUserListUserCase;
        this.connectCameraDeviceUseCase = connectCameraDeviceUseCase;
        this.disconnectCameraDeviceUseCase = disconnectCameraDeviceUseCase;
        this.connectRtmpServerUseCase = connectRtmpServerUseCase;
        this.disconnectRtmpServerUseCase = disconnectRtmpServerUseCase;
        this.sendSpsPpsUseCase = sendSpsPpsUseCase;
        this.annexH264UseCase = annexH264UseCase;
        this.getCameraSrceenshotUseCase = getCameraSrceenshotUseCase;
        this.cameraModelDataMapper = cameraModelDataMapper;
        this.rtmpServUrlMapper = rtmpServUrlMapper;
    }

    public void setView(@NonNull CameraListView view) {
        this.viewListView = view;
    }

    @Override
    public void resume() {
    }

    @Override
    public void pause() {
    }

    @Override
    public void destroy() {
        this.viewListView = null;
        stopAnnexH264();
        this.getCameraListUseCase.dispose();
        this.connectCameraDeviceUseCase.dispose();
        this.disconnectCameraDeviceUseCase.dispose();
        this.connectRtmpServerUseCase.dispose();
        this.disconnectRtmpServerUseCase.dispose();
        this.sendSpsPpsUseCase.dispose();
        this.annexH264UseCase.dispose();
    }

    /**
     * Initializes the presenter by start retrieving the camera list.
     */
    public void initialize() {
        this.loadCameraList();
    }

    /**
     * Loads all cameras.
     */
    private void loadCameraList() {
        this.hideViewRetry();
        this.showViewLoading();
        this.getCameraList();
    }

    private boolean isMainRate() {
        return Cache.readBoolean(SharedPreferencesKey.KEY_MAIN_RATE,
                SharedPreferencesKey.KEY_MAIN_RATE_DEFAULT);
    }

    public void onCameraClicked(CameraModel cameraModel) {

        if (mSelectCamera != null) {
            if (mSelectCamera.getStatus() == Camera.STATUS_CONNECTING) {
                ((BaseFragment) viewListView).showToastMessage("正在连接摄像头");
                return;
            } else if (mSelectCamera.getStatus() == Camera.STATUS_CONNECTED) {
                boolean isSelectCamera = mSelectCamera.equals(cameraModel);
                resetCamera();
                if (isSelectCamera)
                    return;
            }
        }
        mSelectCamera = cameraModel;
        mSelectCamera.setStatus(Camera.STATUS_CONNECTING);

        this.connectCameraDeviceUseCase.execute(new CameraDeviceObserver(),
                ConnectCameraDevice.Params.forUser(mSelectCamera.getIP(),
                        mSelectCamera.getPort(), isMainRate()));

        this.viewListView.viewCamera(cameraModel);
    }

    public void onButtonConnectRtmpSerClick(String serAddr) {
        this.viewListView.onConnectRtmpServerStart();
        this.rtmpServUrl = serAddr;
        this.connectRtmpServerUseCase.execute(new RtmpServerObserver(),
                ConnectRtmpServer.Params.forUser(serAddr));
    }

    public void onButtonDisconnectRtmpSerClick() {
        disconnectRtmpSer();
    }

    public void onButtonAnnexH264Click() {
        if (mCameraDevice == null) {
            ((BaseFragment) viewListView).showToastMessage("摄像头已断开");
            return;
        }
        if (mSerId == -1) {
            ((BaseFragment) viewListView).showToastMessage("RTMP服务器连接出错");
            return;
        }
        CameraListPresenter.this.viewListView.onAnnexH264Start();
        mCameraDevice.setPushing(true);
        this.sendSpsPpsUseCase.execute(new SpsPpsObserver(),
                SendSpsPps.Params.forUser(mCameraDevice, mSerId));
    }

    public void onButtonStopAnnexH264Click() {
        stopAnnexH264();
    }

    public void onButtonAddCameraClick() {
        this.viewListView.showAddCameraDialog("192.168.1.1", "8888");
    }

    public void onAddCamera(String ipAddr, String port) {
        if (cameraModelsCollection == null)
            cameraModelsCollection = new ArrayList<CameraModel>();
        int p = 8888;
        try {
            p = Integer.parseInt(port);
        } catch (NumberFormatException e) {
            e.printStackTrace();
        }
        cameraModelsCollection.add(new CameraModel(ipAddr, p, null));
        CameraListPresenter.this.hideViewLoading();
        this.viewListView.renderUserList(cameraModelsCollection);
    }

    public void onButtonShowRtspClick() {
        if (mCameraDevice != null && !TextUtils.isEmpty(mCameraDevice.getRtspUrl())) {
            Log.d(TAG, "getRtspUrl:" + mCameraDevice.getRtspUrl());
            VideoActivity.intentTo(
                    ((CameraListFragment) viewListView).getActivity(),
                    mCameraDevice.getRtspUrl(), mCameraDevice.getIpAddress());
        } else {
            ((BaseFragment) viewListView).showToastMessage("摄像头未连接");
        }
    }

    public void onButtonShowRtmpClick() {
        if (mCameraDevice != null && mCameraDevice.isPushing()
                && !TextUtils.isEmpty(this.rtmpServUrl)) {
            String rtmpUrl = this.rtmpServUrlMapper.transform(this.rtmpServUrl);
            Log.d(TAG, "rtmpUrl:" + rtmpUrl);
            VideoActivity.intentTo(
                    ((CameraListFragment) viewListView).getActivity(),
                    rtmpUrl, "RTMP");
        } else {
            ((BaseFragment) viewListView).showToastMessage("RTMP视频流未发布");
        }
    }

    private void disconnectRtmpSer() {
        if (this.mCameraDevice != null) {
            mCameraDevice.setPushing(false);
        }
        if (this.viewListView != null) {
            this.viewListView.onDisconnectRtmpServer();
        }
        this.disconnectRtmpServerUseCase.executeOnNewThread(new DisconnectRtmpServerObserver(),
                DisconnectRtmpServer.Params.forUser(mSerId));
    }

    private void stopAnnexH264() {
        disconnectRtmpSer();
        resetCamera();
    }

    private void showViewLoading() {
        this.viewListView.showLoading();
    }

    private void hideViewLoading() {
        this.viewListView.hideLoading();
    }

    private void showViewRetry() {
        this.viewListView.showRetry();
    }

    private void hideViewRetry() {
        this.viewListView.hideRetry();
    }

    private void showErrorMessage(ErrorBundle errorBundle) {
        String errorMessage = ErrorMessageFactory.create(this.viewListView.context(),
                errorBundle.getException());
        this.viewListView.showError(errorMessage);
    }

    private void showCamerasCollectionInView(Collection<Camera> camerasCollection) {
        if (cameraModelsCollection == null)
            cameraModelsCollection = new ArrayList<CameraModel>();
        cameraModelsCollection.addAll(this.cameraModelDataMapper.transform(camerasCollection));
        this.viewListView.renderUserList(cameraModelsCollection);
    }

    private void getCameraList() {
        String name = readString(
                SharedPreferencesKey.KEY_ACCOUNT_NAME,
                SharedPreferencesKey.KEY_ACCOUNT_NAME_DEFAULT);
        String password = Cache.readString(
                SharedPreferencesKey.KEY_ACCOUNT_PASSWORD,
                SharedPreferencesKey.KEY_ACCOUNT_PASSWORD_DEFAULT);
        this.getCameraListUseCase.execute(new CameraListObserver(),
                GetCameraList.Params.forUser(name,
                        password));
    }

    private void resetCamera() {
        if (mSelectCamera != null) {
            mSelectCamera.setStatus(Camera.STATUS_DISCONNECT);
            if (this.viewListView != null) {
                this.viewListView.viewCamera(mSelectCamera);
            }
            mSelectCamera = null;
        }

        if (mCameraDevice != null) {
            mCameraDevice.setPushing(false);
            disconnectCameraDeviceUseCase.executeOnNewThread(new DisconnectCameraDeviceObserver(),
                    DisconnectCameraDevice.Params.forUser(mCameraDevice));
        }

    }

    private final class CameraListObserver extends DefaultObserver<List<Camera>> {

        @Override
        public void onComplete() {
            CameraListPresenter.this.hideViewLoading();
        }

        @Override
        public void onError(Throwable e) {
            e.printStackTrace();
            if (cameraModelsCollection != null)
                return;
            CameraListPresenter.this.hideViewLoading();
            CameraListPresenter.this.showErrorMessage(new DefaultErrorBundle(((Exception) e)));
            CameraListPresenter.this.showViewRetry();
        }

        @Override
        public void onNext(List<Camera> cameras) {
            CameraListPresenter.this.showCamerasCollectionInView(cameras);
        }
    }

    private final class CameraDeviceObserver extends DefaultObserver<CameraDevice> {

        @Override
        public void onComplete() {
            mSelectCamera.setStatus(Camera.STATUS_CONNECTED);
            CameraListPresenter.this.viewListView.viewCamera(mSelectCamera);
            if (mSerId != -1) {
                CameraListPresenter.this.viewListView.onAnnexH264ButtonEnabled();
            }
        }

        @Override
        public void onError(Throwable e) {
            e.printStackTrace();
            ((BaseFragment) viewListView).showToastMessage("连接摄像头" + mSelectCamera.getIP() + "出错");
            mSelectCamera.setStatus(Camera.STATUS_DISCONNECT);
            CameraListPresenter.this.viewListView.viewCamera(mSelectCamera);
        }

        @Override
        public void onNext(CameraDevice device) {
            mCameraDevice = device;
            if (!TextUtils.isEmpty(mCameraDevice.getSnapshotUri()))
                CameraListPresenter.this.getCameraSrceenshotUseCase.execute(new SrceenshotObserver(),
                        GetCameraSrceenshot.Params.forUser(mCameraDevice.getSnapshotUri()));
        }
    }

    private final class DisconnectCameraDeviceObserver extends DefaultObserver<Boolean> {

        @Override
        public void onComplete() {
            if (mCameraDevice != null) {
                synchronized (mCameraDevice) {
                    mCameraDevice = null;
                }
            }
        }

        @Override
        public void onError(Throwable e) {
            e.printStackTrace();
            if (mCameraDevice != null) {
                synchronized (mCameraDevice) {
                    mCameraDevice = null;
                }
            }
        }

        @Override
        public void onNext(Boolean b) {
        }
    }

    private final class RtmpServerObserver extends DefaultObserver<Integer> {

        @Override
        public void onComplete() {
            Log.d("RtmpServerObserver", "onComplete");
            CameraListPresenter.this.viewListView.onConnectRtmpServerComplete();
            if (mCameraDevice != null) {
                CameraListPresenter.this.viewListView.onAnnexH264ButtonEnabled();
            }
        }

        @Override
        public void onError(Throwable e) {
            e.printStackTrace();
            CameraListPresenter.this.viewListView.onConnectRtmpServerError();
        }

        @Override
        public void onNext(Integer serId) {
            mSerId = serId;
        }
    }

    private final class DisconnectRtmpServerObserver extends DefaultObserver<Boolean> {

        @Override
        public void onComplete() {
            Log.d("DisconnectRtmp", "onComplete");
            if (mSerId != -1) {
                synchronized (mSerId) {
                    mSerId = -1;
                }
            }
        }

        @Override
        public void onError(Throwable e) {
            e.printStackTrace();
            if (mSerId != -1) {
                synchronized (mSerId) {
                    mSerId = -1;
                }
            }
        }

        @Override
        public void onNext(Boolean b) {

        }
    }

    private final class SpsPpsObserver extends DefaultObserver<Boolean> {

        @Override
        public void onComplete() {
            Log.d("SpsPpsObserver", "onComplete");
            CameraListPresenter.this.annexH264UseCase.execute(new AnnexH264Observer(),
                    AnnexH264.Params.forUser(mCameraDevice, mSerId));
        }

        @Override
        public void onError(Throwable e) {
            e.printStackTrace();
            Log.d("SpsPpsObserver", "onError");
            CameraListPresenter.this.showErrorMessage(new DefaultErrorBundle(((Exception) e)));
            CameraListPresenter.this.viewListView.onAnnexH264Error();
        }

        @Override
        public void onNext(Boolean b) {
            Log.d("SpsPpsObserver", "onNext");
        }
    }

    private final class AnnexH264Observer extends DefaultObserver<Boolean> {

        @Override
        public void onComplete() {
            Log.d("AnnexH264Observer", "onComplete");
        }

        @Override
        public void onError(Throwable e) {
            e.printStackTrace();
            Log.d("AnnexH264Observer", "onError");
            CameraListPresenter.this.showErrorMessage(new DefaultErrorBundle(((Exception) e)));
            CameraListPresenter.this.viewListView.onAnnexH264Error();
            if (mCameraDevice != null && mSerId != -1) {
                CameraListPresenter.this.viewListView.onAnnexH264ButtonEnabled();
            }
        }

        @Override
        public void onNext(Boolean b) {
            Log.d("AnnexH264Observer", "onNext");
        }
    }

    private final class SrceenshotObserver extends DefaultObserver<Bitmap> {

        @Override
        public void onComplete() {
            Log.d("SrceenshotObserver", "onComplete");
            CameraListPresenter.this.viewListView.viewCamera(mSelectCamera);
        }

        @Override
        public void onError(Throwable e) {
            e.printStackTrace();
            Log.d("SrceenshotObserver", "onError");
        }

        @Override
        public void onNext(Bitmap bitmap) {
            Log.d("SrceenshotObserver", "onNext");
            mSelectCamera.setScreenshot(bitmap);
        }
    }
}
