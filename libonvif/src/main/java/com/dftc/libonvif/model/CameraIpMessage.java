package com.dftc.libonvif.model;

import android.os.Parcel;
import android.os.Parcelable;

/**
 * █████▒█    ██  ▄████▄   ██ ▄█▀       ██████╗ ██╗   ██╗ ██████╗
 * ▓██   ▒ ██  ▓██▒▒██▀ ▀█   ██▄█▒        ██╔══██╗██║   ██║██╔════╝
 * ▒████ ░▓██  ▒██░▒▓█    ▄ ▓███▄░        ██████╔╝██║   ██║██║  ███╗
 * ░▓█▒  ░▓▓█  ░██░▒▓▓▄ ▄██▒▓██ █▄        ██╔══██╗██║   ██║██║   ██║
 * ░▒█░   ▒▒█████▓ ▒ ▓███▀ ░▒██▒ █▄       ██████╔╝╚██████╔╝╚██████╔╝
 * ▒ ░   ░▒▓▒ ▒ ▒ ░ ░▒ ▒  ░▒ ▒▒ ▓▒       ╚═════╝  ╚═════╝  ╚═════╝
 * ░     ░░▒░ ░ ░   ░  ▒   ░ ░▒ ▒░
 * ░ ░    ░░░ ░ ░ ░        ░ ░░ ░
 * ░     ░ ░      ░  ░
 * ░
 * Created by Administrator on 2016/5/13 0013
 * <p>
 * Description:
 * Author: newstrong
 * Update: newstrong(2016.05.13 14:24)
 */
public class CameraIpMessage implements Parcelable {
    public int mode;//0:dhcp;1:固定ip
    public String ipAddr;

    public CameraIpMessage() {
    }

    public CameraIpMessage(Parcel parcel) {
        this.mode = parcel.readInt();
        this.ipAddr = parcel.readString();
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeInt(mode);
        parcel.writeString(ipAddr);
    }

    public static final Parcelable.Creator<CameraIpMessage> CREATOR = new Parcelable.Creator<CameraIpMessage>() {
        @Override
        public CameraIpMessage createFromParcel(Parcel parcel) {
            return new CameraIpMessage(parcel);
        }

        @Override
        public CameraIpMessage[] newArray(int i) {
            return new CameraIpMessage[i];
        }
    };

}
