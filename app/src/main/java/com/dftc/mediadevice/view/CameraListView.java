/**
 * Copyright (C) 2014 android10.org. All rights reserved.
 *
 * @author Fernando Cejas (the android10 coder)
 */
package com.dftc.mediadevice.view;

import com.dftc.mediadevice.model.CameraModel;

import java.util.Collection;

/**
 * Interface representing a View in a model view presenter (MVP) pattern.
 * In this case is used as a view representing a list of {@link CameraModel}.
 */
public interface CameraListView extends LoadDataView {
    /**
     * Render a user list in the UI.
     *
     * @param cameraModelCollection The collection of {@link CameraModel} that will be shown.
     */
    void renderUserList(Collection<CameraModel> cameraModelCollection);

    /**
     * View a {@link CameraModel} profile/details.
     *
     * @param cameraModel The user that will be shown.
     */
    void viewCamera(CameraModel cameraModel);

    void onConnectRtmpServerStart();

    void onConnectRtmpServerError();

    void onConnectRtmpServerComplete();

    void onDisconnectRtmpServer();

    void onAnnexH264ButtonEnabled();

    void onAnnexH264Start();

    void onAnnexH264Error();

    void showAddCameraDialog(String ipAddr, String port);
}
