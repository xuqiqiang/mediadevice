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
 * <p/>
 * Description:
 * Author: newstrong
 * Update: newstrong(2016.05.13 14:35)
 */
public class MediaMessage implements Parcelable{
    private static MediaMessage INSTANCE;

    public int width;	/* required element of type xsd:int */
    public int height;	/* required element of type xsd:int */
    public int frameRateLimit;	/* required element of type xsd:int */
    public int encodingInterval;	/* required element of type xsd:int */
    public int bitrateLimit;	/* required element of type xsd:int */

    public static MediaMessage createMainMedia() {
        MediaMessage msg = new MediaMessage();
        msg.bitrateLimit = 2048;
        msg.encodingInterval = 25;
        msg.frameRateLimit = 25;
        msg.height = 720;
        msg.width = 1280;
        return msg;
    }

    public static MediaMessage createSubMedia() {
        MediaMessage msg = new MediaMessage();
        msg.bitrateLimit = 256;
        msg.encodingInterval = 25;
        msg.frameRateLimit = 25;
        msg.height = 288;
        msg.width = 352;
        return msg;
    }

    private MediaMessage(){}
    public static MediaMessage getInstance(){
        if(INSTANCE==null){
            INSTANCE=new MediaMessage();
        }
        return INSTANCE;
    }
    public MediaMessage(Parcel parcel){
        this.width = parcel.readInt();
        this.height = parcel.readInt();
        this.frameRateLimit = parcel.readInt();
        this.encodingInterval = parcel.readInt();
        this.bitrateLimit = parcel.readInt();
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeInt(width);
        parcel.writeInt(height);
        parcel.writeInt(frameRateLimit);
        parcel.writeInt(encodingInterval);
        parcel.writeInt(bitrateLimit);
    }

    public static final Parcelable.Creator<MediaMessage> CREATOR = new Parcelable.Creator<MediaMessage>() {
        @Override
        public MediaMessage createFromParcel(Parcel parcel) {
            return new MediaMessage(parcel);
        }

        @Override
        public MediaMessage[] newArray(int i) {
            return new MediaMessage[i];
        }
    };

}
