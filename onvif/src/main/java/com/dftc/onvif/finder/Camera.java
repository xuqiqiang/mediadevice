package com.dftc.onvif.finder;

import java.util.ArrayList;
import java.util.UUID;

public class Camera {
	private String mIP;
	private int mPort;
	private String mUUID;
	
	public static final int STATUS_DISCONNECT = 0, STATUS_CONNECTING = 1, STATUS_CONNECTED = 2;
	private int mStatus = STATUS_DISCONNECT;
	
	public Camera(String ip, int port, String uuid){
		mIP = ip;
		mPort = port;
		mUUID = uuid;
	}
	
	public String getIP() {
		return mIP;
	}
	
	public int getPort() {
		return mPort;
	}
	
	public String getUUID() {
		return mUUID;
	}
	
	public void setStatus(int status) {
	    mStatus = status;
    }
	
	public int getStatus() {
        return mStatus;
    }
	
	@Override
    public String toString() {
        return "Camera{" +
                "ip='" + mIP + '\'' +
                ", port='" + mPort + '\'' +
                ", UUID='" + mUUID + '\'' +
                '}';
    }
}