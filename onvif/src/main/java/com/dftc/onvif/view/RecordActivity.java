package com.dftc.onvif.view;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Locale;

import org.videolan.libvlc.EventHandler;
import org.videolan.libvlc.IVideoPlayer;
import org.videolan.libvlc.LibVLC;
import org.videolan.libvlc.LibVlcException;
import org.videolan.libvlc.WeakHandler;

import android.app.Activity;
import android.content.res.Configuration;
import android.graphics.ImageFormat;
import android.graphics.PixelFormat;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.SurfaceHolder;
import android.view.SurfaceHolder.Callback;
import android.view.SurfaceView;
import android.view.ViewGroup.LayoutParams;
import android.view.Window;

import com.dftc.onvif.R;

public class RecordActivity extends Activity implements IVideoPlayer {

    public final static String TAG = "DEBUG/VideoPlayerActivity";

    private SurfaceHolder surfaceHolder = null;
    private LibVLC mLibVLC = null;

    private int mVideoHeight;
    private int mVideoWidth;
    private int mSarDen;
    private int mSarNum;
    private static final int SURFACE_SIZE = 3;

    private SurfaceView surfaceView = null;

    // private static RecordActivity instance;
    private static Runnable event;

    public static void setEvent(Runnable event) {
        RecordActivity.event = event;
    }

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        // instance = this;
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        setContentView(R.layout.record_view);
        setupView();

        try {
            mLibVLC = LibVLC.getInstance();
            if (mLibVLC != null) {
                EventHandler em = EventHandler.getInstance();
                em.addHandler(eventHandler);

                Log.d(TAG, "mLibVLC.isPlaying():" + mLibVLC.isPlaying());
                // if (!mLibVLC.isPlaying()) {
                mLibVLC.play();
                // }
            }
        } catch (LibVlcException e) {
            e.printStackTrace();
        }

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

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        setSurfaceSize(mVideoWidth, mVideoHeight, mSarNum, mSarDen);
        super.onConfigurationChanged(newConfig);
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
            mLibVLC.attachSurface(holder.getSurface(), RecordActivity.this);
            if (event != null) {
                new Handler().postDelayed(new Runnable() {

                    @Override
                    public void run() {
                        new Thread() {

                            @Override
                            public void run() {
                                event.run();
                                finish();
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

    public final Handler mHandler = new VideoPlayerHandler(this);

    private static class VideoPlayerHandler extends WeakHandler<RecordActivity> {
        public VideoPlayerHandler(RecordActivity owner) {
            super(owner);
        }

        @Override
        public void handleMessage(Message msg) {
            RecordActivity activity = getOwner();
            if (activity == null) // WeakReference could be GC'ed early
                return;

            switch (msg.what) {
            case SURFACE_SIZE:
                activity.changeSurfaceSize();
                break;
            }
        }
    };

    private void changeSurfaceSize() {
        Log.d(TAG, "changeSurfaceSize");
        surfaceHolder.setFixedSize(mVideoWidth, mVideoHeight);
        LayoutParams lp = surfaceView.getLayoutParams();
        lp.width = 1;// dw;
        lp.height = 1;// dh;
        surfaceView.setLayoutParams(lp);
        surfaceView.invalidate();
    }

    private final Handler eventHandler = new VideoPlayerEventHandler(this);

    private static class VideoPlayerEventHandler extends
            WeakHandler<RecordActivity> {
        public VideoPlayerEventHandler(RecordActivity owner) {
            super(owner);
        }

        @Override
        public void handleMessage(Message msg) {
            RecordActivity activity = getOwner();
            if (activity == null)
                return;
            Log.d(TAG, "Event = " + msg.getData().getInt("event"));
            switch (msg.getData().getInt("event")) {
            case EventHandler.MediaPlayerPlaying:
                Log.i(TAG, "MediaPlayerPlaying");
                break;
            case EventHandler.MediaPlayerPaused:
                Log.i(TAG, "MediaPlayerPaused");
                break;
            case EventHandler.MediaPlayerStopped:
                Log.i(TAG, "MediaPlayerStopped");
                break;
            case EventHandler.MediaPlayerEndReached:
                Log.i(TAG, "MediaPlayerEndReached");
                // activity.finish();
                break;
            case EventHandler.MediaPlayerVout:
                Log.i(TAG, "MediaPlayerEndReached");
                // activity.finish();
                break;
            default:
                Log.d(TAG, "Event not handled");
                break;
            }
        }
    }

    @Override
    protected void onDestroy() {
        EventHandler em = EventHandler.getInstance();
        em.removeHandler(eventHandler);
        if (mLibVLC != null) {
            mLibVLC.pause();
            // mLibVLC.stop();
        }

        super.onDestroy();
    };

    /**
     * Convert time to a string
     * 
     * @param millis
     *            e.g.time/length from file
     * @return formated string (hh:)mm:ss
     */
    public static String millisToString(long millis) {
        boolean negative = millis < 0;
        millis = java.lang.Math.abs(millis);

        millis /= 1000;
        int sec = (int) (millis % 60);
        millis /= 60;
        int min = (int) (millis % 60);
        millis /= 60;
        int hours = (int) millis;

        String time;
        DecimalFormat format = (DecimalFormat) NumberFormat
                .getInstance(Locale.US);
        format.applyPattern("00");
        if (millis > 0) {
            time = (negative ? "-" : "") + hours + ":" + format.format(min)
                    + ":" + format.format(sec);
        } else {
            time = (negative ? "-" : "") + min + ":" + format.format(sec);
        }
        return time;
    }

    public void setSurfaceSize(int width, int height, int sar_num, int sar_den) {
        if (width * height == 0)
            return;

        mVideoHeight = height;
        mVideoWidth = width;
        mSarNum = sar_num;
        mSarDen = sar_den;
        Message msg = mHandler.obtainMessage(SURFACE_SIZE);
        mHandler.sendMessage(msg);
    }

    @Override
    public void setSurfaceSize(int width, int height, int visible_width,
            int visible_height, int sar_num, int sar_den) {
        mVideoHeight = height;
        mVideoWidth = width;
        mSarNum = sar_num;
        mSarDen = sar_den;
        Message msg = mHandler.obtainMessage(SURFACE_SIZE);
        mHandler.sendMessage(msg);
    }

}
