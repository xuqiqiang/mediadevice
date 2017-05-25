package com.dftc.onvif.finder;

import java.util.UUID;

public class CameraDevice {
    private static int idIndex = 0;
    public UUID uuid;
    public String serviceURL;
    private int id;
    private String name;
    private String ipAddr;
    private boolean isOnline = false;
    private String rtspUri = "";
    private String snapshotUri = "";

    public int width;
    public int height;
    public int rate;

    public String username;
    public String password;

    private boolean mainRate;

    private boolean pushing;

    public CameraDevice(UUID uuid, String serviceURL, boolean mainRate) {
        this.uuid = uuid;
        this.serviceURL = serviceURL;
        this.mainRate = mainRate;
    }

    public void setSecurity(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public void setProperties(int width, int height, int rate) {
        this.width = width;
        this.height = height;
        this.rate = rate;
    }

    public void initId() {
        this.id = idIndex++;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setIpAddr(String ipAddr) {
        this.ipAddr = ipAddr;
    }

    public void setOnline(boolean isOnline) {
        this.isOnline = isOnline;
    }

    public int getId() {
        return this.id;
    }

    public void setRtspUrl(String rtspUri) {
        this.rtspUri = rtspUri;
    }

    public String getRtspUrl() {
        return this.rtspUri;
    }

    public void setSnapshotUri(String snapshotUri) {
        this.snapshotUri = snapshotUri;
    }

    public String getSnapshotUri() {
        return this.snapshotUri;
    }

    public String getName() {
        return this.name;
    }

    public String getIpAddress() {
        return this.ipAddr;
    }

    public boolean isMainRate() {
        return this.mainRate;
    }

    public boolean isOnline() {
        return this.isOnline;
    }

    public boolean isPushing() {
        return this.pushing;
    }

    public void setPushing(boolean pushing) {
        this.pushing = pushing;
    }
}
