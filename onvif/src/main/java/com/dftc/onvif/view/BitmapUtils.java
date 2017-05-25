package com.dftc.onvif.view;

import android.os.Environment;

public class BitmapUtils {

    public static String getSDPath() {
        boolean hasSDCard = Environment.getExternalStorageState().equals(
                Environment.MEDIA_MOUNTED);
        if (hasSDCard) {
            return Environment.getExternalStorageDirectory().toString();
        } else
            return Environment.getDownloadCacheDirectory().toString();
    }
}
