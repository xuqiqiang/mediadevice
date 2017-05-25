package com.dftc.onvif.view;

import org.videolan.libvlc.IVideoPlayer;
import org.videolan.libvlc.LibVLC;
import org.videolan.libvlc.LibVlcException;
import org.videolan.libvlc.WeakHandler;

import android.content.Context;
import android.graphics.ImageFormat;
import android.graphics.PixelFormat;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.SurfaceHolder;
import android.view.SurfaceHolder.Callback;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.LinearLayout;

import com.dftc.onvif.R;

public class DesktopLayout extends LinearLayout implements IVideoPlayer {

    public final static String TAG = "VideoPlayerActivity";

    private Context context;

    private SurfaceHolder surfaceHolder = null;
    private LibVLC mLibVLC = null;

    private int mVideoHeight;
    private int mVideoWidth;
    private static final int SURFACE_SIZE = 3;
    private static final int CLOSE_DESK = 4;

    private SurfaceView surfaceView = null;

    private WindowManager mWindowManager;
    private WindowManager.LayoutParams mLayout;

    private boolean runEvent;
    private Runnable event;

    public DesktopLayout(Context context) {
        super(context);
        this.context = context;

        createWindowManager();

        setOrientation(LinearLayout.VERTICAL);

        this.setLayoutParams(new LayoutParams(LayoutParams.WRAP_CONTENT,
                LayoutParams.WRAP_CONTENT));

        View view = LayoutInflater.from(context).inflate(R.layout.record_view,
                null);
        this.addView(view);

        try {
            mLibVLC = LibVLC.getInstance();
            if (mLibVLC != null) {
                Log.d(TAG, "mLibVLC.isPlaying():" + mLibVLC.isPlaying());
                mLibVLC.play();
            }
        } catch (LibVlcException e) {
            e.printStackTrace();
        }

        setupView();
    }

    /**
     * 初始化组件
     */
    private void setupView() {
        surfaceView = (SurfaceView) findViewById(R.id.main_surface);
        surfaceHolder = surfaceView.getHolder();
        surfaceHolder.setFormat(PixelFormat.RGBX_8888);
        surfaceHolder.addCallback(mSurfaceCallback);

    }

    /**
     * 设置WindowManager
     */
    private void createWindowManager() {
        // 取得系统窗体
        mWindowManager = (WindowManager) context.getSystemService("window");

        // 窗体的布局样式
        mLayout = new WindowManager.LayoutParams();

        // 设置窗体显示类型——TYPE_SYSTEM_ALERT(系统提示)
        mLayout.type = WindowManager.LayoutParams.TYPE_SYSTEM_ALERT;

        // 设置窗体焦点及触摸：
        // FLAG_NOT_FOCUSABLE(不能获得按键输入焦点)
        mLayout.flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;

        // 设置显示的模式
        mLayout.format = PixelFormat.RGBA_8888;

        // 设置对齐的方法
        mLayout.gravity = Gravity.TOP | Gravity.LEFT;

        // 设置窗体宽度和高度
        mLayout.width = WindowManager.LayoutParams.WRAP_CONTENT;
        mLayout.height = WindowManager.LayoutParams.WRAP_CONTENT;

    }

    /**
     * 显示DesktopLayout
     */
    public void showDesk() {
        mWindowManager.addView(this, mLayout);
    }

    /**
     * 关闭DesktopLayout
     */
    public void closeDesk() {
        mWindowManager.removeView(this);
    }

    public void setEvent(Runnable event) {
        this.event = event;
    }

    /**
     * attach and disattach surface to the lib
     */
    private final SurfaceHolder.Callback mSurfaceCallback = new Callback() {
        @Override
        public void surfaceChanged(SurfaceHolder holder, int format, int width,
                int height) {
            if (format == PixelFormat.RGBX_8888)
                Log.d(TAG, "Pixel format is RGBX_8888");
            else if (format == PixelFormat.RGB_565)
                Log.d(TAG, "Pixel format is RGB_565");
            else if (format == ImageFormat.YV12)
                Log.d(TAG, "Pixel format is YV12");
            else
                Log.d(TAG, "Pixel format is other/unknown");
            mLibVLC.attachSurface(holder.getSurface(), DesktopLayout.this);
            if (event != null && !runEvent) {
                runEvent = true;
                new Handler().postDelayed(new Runnable() {

                    @Override
                    public void run() {
                        new Thread() {

                            @Override
                            public void run() {
                                event.run();
                                Message msg = mHandler
                                        .obtainMessage(CLOSE_DESK);
                                mHandler.sendMessage(msg);
                            }
                        }.start();
                    }
                }, 1000);
            }
        }

        @Override
        public void surfaceCreated(SurfaceHolder holder) {
        }

        @Override
        public void surfaceDestroyed(SurfaceHolder holder) {
            mLibVLC.detachSurface();
        }
    };

    public Handler mHandler = new VideoPlayerHandler(this);

    private class VideoPlayerHandler extends WeakHandler<DesktopLayout> {
        public VideoPlayerHandler(DesktopLayout owner) {
            super(owner);
        }

        @Override
        public void handleMessage(Message msg) {
            DesktopLayout activity = getOwner();
            if (activity == null) // WeakReference could be GC'ed early
                return;

            switch (msg.what) {
            case SURFACE_SIZE:
                activity.changeSurfaceSize();
                break;
            case CLOSE_DESK:
                closeDesk();
                break;
            }
        }
    };

    private void changeSurfaceSize() {
        Log.d(TAG, "changeSurfaceSize");
        surfaceHolder.setFixedSize(mVideoWidth, mVideoHeight);
        ViewGroup.LayoutParams lp = surfaceView.getLayoutParams();
        lp.width = 1;
        lp.height = 1;
        surfaceView.setLayoutParams(lp);
        surfaceView.invalidate();
    }

    @Override
    public void setSurfaceSize(int width, int height, int visible_width,
            int visible_height, int sar_num, int sar_den) {
        mVideoHeight = height;
        mVideoWidth = width;
        Message msg = mHandler.obtainMessage(SURFACE_SIZE);
        mHandler.sendMessage(msg);
    }
}
