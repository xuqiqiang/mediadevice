package com.dftc.mediadevice.data.cache;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Environment;
import android.text.TextUtils;

import java.io.File;

public class Cache {
    private static final String DIR = "MediaDevice";
    private static String projectPath = Environment.getExternalStorageDirectory().getPath()
            + File.separator + DIR;
    private static SharedPreferences mPreferences;
    private static SharedPreferences.Editor editor;

    public static void createDir(String path) {
        if (TextUtils.isEmpty(path))
            return;

        if (path.startsWith(File.separator))
            path = path.substring(1);

        String dir_name_list[] = path.split(File.separator);

        String path_name = projectPath;
        File file = new File(path_name);
        if (!file.exists()) {// 目录存在返回true
            file.mkdirs();// 创建一个目录
        }

        for (String dir_name : dir_name_list) {
            path_name += File.separator + dir_name;
            file = new File(path_name);

            if (!file.exists()) {// 目录存在返回true
                file.mkdirs();// 创建一个目录
            }
        }
    }

    public static String getAbsolutePath(String path) {
        if (path.startsWith(File.separator))
            return Cache.projectPath + path;
        else
            return Cache.projectPath + File.separator + path;
    }

    public static void initSharedPreferences(Context context) {
        initSharedPreferences(context, DIR);
    }

    public static void initSharedPreferences(Context context, String name) {
        mPreferences = context.getSharedPreferences(name,
                Activity.MODE_PRIVATE);
        editor = mPreferences.edit();
    }

    public static int readInt(String name, int arg) {

        return mPreferences.getInt(name, arg);
    }

    public static void writeInt(String name, int a) {

        editor.putInt(name, a);

        editor.commit();
    }

    public static float readFloat(String name, float arg) {
        return mPreferences.getFloat(name, arg);
    }

    public static void writeFloat(String name, float a) {
        editor.putFloat(name, a);
        editor.commit();
    }

    public static double readDouble(String name, double arg) {

        double result = arg;
        try {
            String str = mPreferences.getString(name, arg + "");
            result = Double.valueOf(str);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;

    }

    public static void writeDouble(String name, double a) {

        editor.putString(name, a + "");
        editor.commit();
    }

    public static String readString(String name, String arg) {

        return mPreferences.getString(name, arg);
    }

    public static void writeString(String name, String a) {

        editor.putString(name, a);

        editor.commit();
    }

    public static Boolean readBoolean(String name, Boolean arg) {
        return mPreferences.getBoolean(name, arg);
    }

    public static void writeBoolean(String name, Boolean a) {

        editor.putBoolean(name, a);

        editor.commit();
    }

}