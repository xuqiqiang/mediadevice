package com.dftc.libonvif.model;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;

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
 * <p/>
 * Description:
 * Author: newstrong
 * Update: newstrong(2016.05.13 13:59)
 */
public class CameraInfomation implements Parcelable {
    public String mac;
    public String deviceAddr;
    public String mediaAddr;
    public String rtspAddrMain;
    public String rtspAddrSub;
    public String serialNumber;
    public boolean ennable;//能否ping通
    public int count = 1;

    //// TODO: 2016/7/17 0017 为了判断是否该重启摄像头
    public boolean isPlayWorking;
    public boolean restarted;
    public boolean canControl = true;

    @Override
    public boolean equals(Object o) {
        if (o instanceof CameraInfomation) {
            return ((CameraInfomation) o).deviceAddr.equals(this.deviceAddr);
        }
        return super.equals(o);
    }


    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(mac);
        parcel.writeString(deviceAddr);
        parcel.writeString(mediaAddr);
        parcel.writeString(rtspAddrMain);
        parcel.writeString(rtspAddrSub);
        parcel.writeString(serialNumber);
        parcel.writeInt(count);
    }

    public CameraInfomation() {
    }

    public CameraInfomation(Parcel in) {
        this.mac = in.readString();
        this.deviceAddr = in.readString();
        this.mediaAddr = in.readString();
        this.rtspAddrMain = in.readString();
        this.rtspAddrSub = in.readString();
        this.serialNumber = in.readString();
        this.count = in.readInt();
    }

    public static final Parcelable.Creator<CameraInfomation> CREATOR = new Creator<CameraInfomation>() {
        @Override
        public CameraInfomation createFromParcel(Parcel parcel) {
            return new CameraInfomation(parcel);
        }

        @Override
        public CameraInfomation[] newArray(int i) {
            return new CameraInfomation[i];
        }
    };

    public String getSpecialIp() {
        String s = rtspAddrMain.replaceFirst("rtsp://", "");
        if (s.contains(":")) {
            return s.split(":")[0];
        }
        return null;
    }
    public String getDeviceSpecialIp() {
        String s = deviceAddr.replaceFirst("http://", "");
        s=s.replaceAll("\\\\","/");
        if (s.contains("/")) {
            String s1 = s.split("/")[0];
            if(s1.contains(":")){
                s1=s1.split(":")[0];
            }
            return s1;
        }
        return null;
    }

    @Override
    public String toString() {
        return "CameraInfomation{" +
                "mac='" + mac + '\'' +
                ", deviceAddr='" + deviceAddr + '\'' +
                ", mediaAddr='" + mediaAddr + '\'' +
                ", rtspAddrMain='" + rtspAddrMain + '\'' +
                ", rtspAddrSub='" + rtspAddrSub + '\'' +
                ", serialNumber='" + serialNumber + '\'' +
                ", ennable=" + ennable +
                ", count=" + count +
                ", isPlayWorking=" + isPlayWorking +
                ", restarted=" + restarted +
                ", canControl=" + canControl +
                '}';
    }
}
