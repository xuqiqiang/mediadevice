package com.dftc.onvif.utils;

import java.io.File;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Environment;
import android.text.TextUtils;

public class Cache {
    public static String rootName = Environment.getExternalStorageDirectory()
            .getPath();

    public static final String dir = "MediaDevice";

    private Context context;
    private String filename;
    private SharedPreferences MyPreferences;
    private SharedPreferences.Editor editor;

    private static Cache instance;

    private Cache(Context context) {
        this.context = context;
        setRootName(dir);
        initSharedPreferences(dir);
    }

    public static Cache getInstance(Context context) {
        if (instance == null)
            instance = new Cache(context);
        return instance;
    }

    public static void setRootName(String name) {
        if (!TextUtils.isEmpty(name))
            rootName = Environment.getExternalStorageDirectory().getPath()
                    + File.separator + name;
        else
            rootName = Environment.getExternalStorageDirectory().getPath();
    }

    /**
     * @param path
     *            CloudPath
     */
    public static void createDir(String path) {
        if (TextUtils.isEmpty(path))
            return;

        if (path.startsWith(File.separator))
            path = path.substring(1);

        String dir_name_list[] = path.split(File.separator);

        String path_name = rootName;
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

    public static String getRealFilePath(String path) {
        if (path.startsWith(File.separator))
            return Cache.rootName + path;
        else
            return Cache.rootName + File.separator + path;
    }

    public static String getRealFilePath(String[] cacheName) {

        String pathename = rootName;
        if (cacheName != null) {
            int i, length = cacheName.length;
            for (i = 0; i < length; i++) {
                pathename += File.separator + cacheName[i];
            }
        }

        return pathename;
    }

    public void initSharedPreferences() {
        filename = context.getPackageName();
        MyPreferences = context.getSharedPreferences(filename,
                Activity.MODE_PRIVATE);

        editor = MyPreferences.edit();
    }

    public void initSharedPreferences(String name) {
        MyPreferences = context.getSharedPreferences(name,
                Activity.MODE_PRIVATE);
        editor = MyPreferences.edit();
    }

    public int read_int(String name, int arg) {

        return MyPreferences.getInt(name, arg);
    }

    public void write_int(String name, int a) {

        editor.putInt(name, a);

        editor.commit();
    }

    public float read_float(String name, float arg) {
        return MyPreferences.getFloat(name, arg);
    }

    public void write_float(String name, float a) {
        editor.putFloat(name, a);
        editor.commit();
    }

    public double read_double(String name, double arg) {

        double result = arg;
        try {
            String str = MyPreferences.getString(name, arg + "");
            result = Double.valueOf(str);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;

    }

    public void write_double(String name, double a) {

        editor.putString(name, a + "");
        editor.commit();
    }

    public String read_String(String name, String arg) {

        return MyPreferences.getString(name, arg);
    }

    public void write_String(String name, String a) {

        editor.putString(name, a);

        editor.commit();
    }

    public Boolean read_Boolean(String name, Boolean arg) {
        return MyPreferences.getBoolean(name, arg);
    }

    public void write_Boolean(String name, Boolean a) {

        editor.putBoolean(name, a);

        editor.commit();
    }

}