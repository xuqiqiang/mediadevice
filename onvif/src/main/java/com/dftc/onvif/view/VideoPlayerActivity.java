package com.dftc.onvif.view;

import android.app.Activity;
import android.app.ProgressDialog;
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
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnSystemUiVisibilityChangeListener;
import android.view.ViewGroup.LayoutParams;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.dftc.onvif.R;

import org.videolan.libvlc.EventHandler;
import org.videolan.libvlc.IVideoPlayer;
import org.videolan.libvlc.LibVLC;
import org.videolan.libvlc.LibVlcException;
import org.videolan.libvlc.Util;
import org.videolan.libvlc.WeakHandler;

import java.io.File;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class VideoPlayerActivity extends Activity implements OnClickListener,
        IVideoPlayer {

    public final static String TAG = "VideoPlayerActivity";

    private SurfaceHolder surfaceHolder = null;
    private LibVLC mLibVLC = null;

    private int mVideoHeight;
    private int mVideoWidth;
    private int mSarDen;
    private int mSarNum;
    private int mUiVisibility = -1;
    private static final int SURFACE_SIZE = 3;

    private static final int SURFACE_BEST_FIT = 0;
    private static final int SURFACE_FIT_HORIZONTAL = 1;
    private static final int SURFACE_FIT_VERTICAL = 2;
    private static final int SURFACE_FILL = 3;
    private static final int SURFACE_16_9 = 4;
    private static final int SURFACE_4_3 = 5;
    private static final int SURFACE_ORIGINAL = 6;
    private int mCurrentSize = SURFACE_BEST_FIT;

    // private String[] mAudioTracks;

    private SurfaceView surfaceView = null;
    private FrameLayout mLayout;
    private TextView mTextTitle;
    private TextView mTextTime;

    private ImageView btnPlayPause;
    private ImageView btnSize;
    private TextView mTextShowInfo;

    private Button snapShot;// 截图

    private Button videoRecord;// 录像

    private boolean isRunning;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.video_player);
        setupView();

        if (Util.isICSOrLater())
            getWindow()
                    .getDecorView()
                    .findViewById(android.R.id.content)
                    .setOnSystemUiVisibilityChangeListener(
                            new OnSystemUiVisibilityChangeListener() {

                                @Override
                                public void onSystemUiVisibilityChange(
                                        int visibility) {
                                    if (visibility == mUiVisibility)
                                        return;
                                    setSurfaceSize(mVideoWidth, mVideoHeight,
                                            mSarNum, mSarDen);
                                    if (visibility == View.SYSTEM_UI_FLAG_VISIBLE) {
                                        Log.d(TAG, "onSystemUiVisibilityChange");
                                    }
                                    mUiVisibility = visibility;
                                }
                            });

        try {
            mLibVLC = LibVLC.getInstance();
            if (mLibVLC != null) {
                EventHandler em = EventHandler.getInstance();
                em.addHandler(eventHandler);
                isRunning = true;
                handler.sendEmptyMessageDelayed(0, 1000);

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
        // surfaceView = new SurfaceView(this);
        // surfaceView.setVisibility(View.INVISIBLE);
        surfaceHolder = surfaceView.getHolder();
        surfaceHolder.setFormat(PixelFormat.RGBX_8888);
        surfaceHolder.addCallback(mSurfaceCallback);
        // new Handler().postDelayed(new Runnable() {
        //
        // @Override
        // public void run() {
        // try {
        // mLibVLC = LibVLC.getInstance();
        // } catch (LibVlcException e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }
        // mLibVLC.attachSurface(surfaceHolder.getSurface(),
        // VideoPlayerActivity.this);//
        // }
        // }, 2000);

        mLayout = (FrameLayout) findViewById(R.id.video_player_overlay);
        mTextTitle = (TextView) findViewById(R.id.video_player_title);

        btnPlayPause = (ImageView) findViewById(R.id.video_player_playpause);
        btnSize = (ImageView) findViewById(R.id.video_player_size);
        mTextTime = (TextView) findViewById(R.id.video_player_time);
        mTextShowInfo = (TextView) findViewById(R.id.video_player_showinfo);

        btnPlayPause.setOnClickListener(this);
        btnSize.setOnClickListener(this);

        snapShot = (Button) findViewById(R.id.snapShot);
        snapShot.setOnClickListener(this);

        videoRecord = (Button) findViewById(R.id.videoRecord);
        videoRecord.setOnClickListener(this);

        mTextTitle.setText(getIntent().getStringExtra("name"));

        pathIsExist();
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();
        if (id == R.id.video_player_playpause) {
            if (mLibVLC.isPlaying()) {
                mLibVLC.pause();
                btnPlayPause.setImageResource(R.drawable.ic_play_selector);
            } else {
                mLibVLC.play();
                btnPlayPause.setImageResource(R.drawable.ic_pause_selector);
            }
        }
        if (id == R.id.video_player_size) {
            if (mCurrentSize < SURFACE_ORIGINAL) {
                mCurrentSize++;
            } else {
                mCurrentSize = 0;
            }
            changeSurfaceSize();
        }
        if (id == R.id.snapShot) {
            snapShot();
        }
        if (id == R.id.videoRecord) {
            videoRecord();
        }

    }

    /**
     * 路径是否存在 不存在则创建
     */
    private void pathIsExist() {
        File dir = new File(BitmapUtils.getSDPath() + "/MediaDevice/");
        if (!dir.exists())
            dir.mkdirs();

        File file = new File(BitmapUtils.getSDPath() + "/MediaDevice/capture/");
        if (!file.exists())
            file.mkdirs();

        File file1 = new File(BitmapUtils.getSDPath() + "/MediaDevice/video/");
        if (!file1.exists())
            file1.mkdirs();
    }

    /**
     * 截图
     */
    private void snapShot() {
        try {
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss");
            String name = df.format(new Date());
            name = BitmapUtils.getSDPath() + "/MediaDevice/capture/" + name
                    + ".png";
            File file = new File(name);
            if (!file.exists())
                file.createNewFile();
            if (mLibVLC.takeSnapShot(name, 640, 360)) {
                Toast.makeText(getApplicationContext(), "已保存", Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(getApplicationContext(), "截图出错", Toast.LENGTH_LONG).show();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 录像和停止录像
     */
    private void videoRecord() {
        try {

            if (mLibVLC.videoIsRecording()) {
                if (mLibVLC.videoRecordStop()) {
                    videoRecord.setText("开始录像");
                    Toast.makeText(getApplicationContext(), "已停止录像", Toast.LENGTH_LONG)
                            .show();
                } else {
                    Toast.makeText(getApplicationContext(), "停止录像出错", Toast.LENGTH_LONG)
                            .show();
                }
            } else {
                SimpleDateFormat df = new SimpleDateFormat(
                        "yyyy-MM-dd HH-mm-ss");
                final String name = df.format(new Date());
                // if (mLibVLC.videoRecordStart(BitmapUtils.getSDPath()
                // + "/MediaDevice/video/" + name)) {

                final ProgressDialog mProgressDialog = new ProgressDialog(this);
                mProgressDialog.setTitle("开始录像");
                mProgressDialog.setMessage("请稍后...");
                mProgressDialog.setCancelable(true);
                mProgressDialog.show();

                new Thread(new Runnable() {

                    @Override
                    public void run() {

                        while (true)
                            try {

                                if (mLibVLC.videoIsRecording()) {
                                    runOnUiThread(new Runnable() {

                                        @Override
                                        public void run() {
                                            videoRecord.setText("停止录像");
                                            Toast.makeText(
                                                    getApplicationContext(),
                                                    "开始录像", Toast.LENGTH_LONG).show();
                                            mProgressDialog.hide();
                                        }
                                    });
                                    return;

                                } else {
                                    mLibVLC.videoRecordStart(BitmapUtils
                                            .getSDPath()
                                            + "/MediaDevice/video/" + name);
                                    Log.d(TAG, "videoRecordStart");
                                }
                                Thread.sleep(1000);

                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                    }
                }).start();
                // } else {
                // Toast.makeText(getApplicationContext(), "开始录像出错", 1000)
                // .show();
                // }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Handler handler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            int time = (int) mLibVLC.getTime();
            int length = (int) mLibVLC.getLength();
            showVideoTime(time, length);
            if (isRunning)
                handler.sendEmptyMessageDelayed(0, 1000);
        }
    };

    private void showVideoTime(int t, int l) {
        mTextTime.setText(millisToString(t));
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
            mLibVLC.attachSurface(holder.getSurface(), VideoPlayerActivity.this);

            // surfaceView.setVisibility(View.INVISIBLE);
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

    private static class VideoPlayerHandler extends
            WeakHandler<VideoPlayerActivity> {
        public VideoPlayerHandler(VideoPlayerActivity owner) {
            super(owner);
        }

        @Override
        public void handleMessage(Message msg) {
            VideoPlayerActivity activity = getOwner();
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
        // get screen size
        int dw = getWindow().getDecorView().getWidth();
        int dh = getWindow().getDecorView().getHeight();

        // getWindow().getDecorView() doesn't always take orientation into
        // account, we have to correct the values
        boolean isPortrait = getResources().getConfiguration().orientation == Configuration.ORIENTATION_PORTRAIT;
        if (dw > dh && isPortrait || dw < dh && !isPortrait) {
            int d = dw;
            dw = dh;
            dh = d;
        }
        if (dw * dh == 0)
            return;
        // compute the aspect ratio
        double ar, vw;
        double density = (double) mSarNum / (double) mSarDen;
        if (density == 1.0) {
            /* No indication about the density, assuming 1:1 */
            vw = mVideoWidth;
            ar = (double) mVideoWidth / (double) mVideoHeight;
        } else {
            /* Use the specified aspect ratio */
            vw = mVideoWidth * density;
            ar = vw / mVideoHeight;
        }

        // compute the display aspect ratio
        double dar = (double) dw / (double) dh;

        // // calculate aspect ratio
        // double ar = (double) mVideoWidth / (double) mVideoHeight;
        // // calculate display aspect ratio
        // double dar = (double) dw / (double) dh;

        switch (mCurrentSize) {
        case SURFACE_BEST_FIT:
            mTextShowInfo.setText(R.string.video_player_best_fit);
            if (dar < ar)
                dh = (int) (dw / ar);
            else
                dw = (int) (dh * ar);
            break;
        case SURFACE_FIT_HORIZONTAL:
            mTextShowInfo.setText(R.string.video_player_fit_horizontal);
            dh = (int) (dw / ar);
            break;
        case SURFACE_FIT_VERTICAL:
            mTextShowInfo.setText(R.string.video_player_fit_vertical);
            dw = (int) (dh * ar);
            break;
        case SURFACE_FILL:
            break;
        case SURFACE_16_9:
            mTextShowInfo.setText(R.string.video_player_16x9);
            ar = 16.0 / 9.0;
            if (dar < ar)
                dh = (int) (dw / ar);
            else
                dw = (int) (dh * ar);
            break;
        case SURFACE_4_3:
            mTextShowInfo.setText(R.string.video_player_4x3);
            ar = 4.0 / 3.0;
            if (dar < ar)
                dh = (int) (dw / ar);
            else
                dw = (int) (dh * ar);
            break;
        case SURFACE_ORIGINAL:
            mTextShowInfo.setText(R.string.video_player_original);
            dh = mVideoHeight;
            dw = mVideoWidth;
            break;
        }

        surfaceHolder.setFixedSize(mVideoWidth, mVideoHeight);
        LayoutParams lp = surfaceView.getLayoutParams();
        lp.width = dw;
        lp.height = dh;
        surfaceView.setLayoutParams(lp);
        surfaceView.invalidate();
    }

    private final Handler eventHandler = new VideoPlayerEventHandler(this);

    private static class VideoPlayerEventHandler extends
            WeakHandler<VideoPlayerActivity> {
        public VideoPlayerEventHandler(VideoPlayerActivity owner) {
            super(owner);
        }

        @Override
        public void handleMessage(Message msg) {
            VideoPlayerActivity activity = getOwner();
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
        isRunning = false;

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
