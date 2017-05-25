package com.dftc.onvif.finder;

import android.util.Base64;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public class RtspClient implements Runnable {
    public static final String DESCRIBE = "DESCRIBE %s RTSP/1.0\r\nCSeq:0\r\nAccept:application/sdp\r\nAuthorization:Basic %s\r\n\r\n";
    public static final String SETUP = "SETUP %s/trackID=1 RTSP/1.0\r\nCSeq:1\r\nAuthorization:Basic %s\r\nTransport:RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=0\r\nUser-Agent:NKPlayer-1.00.00.081112\r\n\r\n";
    public static final String PLAY = "PLAY %s RTSP/1.0\r\nCSeq:2\r\nAuthorization:Basic %s\r\nRate-Control:yes\r\nScale:1.000\r\nUser-Agent:NKPlayer-1.00.00.081112\r\n\r\n";

    interface OnRtspListener {
        public void OnRtspStartPlay(String uri);
    }

    private String mUsername, mPassword, mUri, mAuthorization;
    private Socket mSocket;
    private OnRtspListener mListener;

    public RtspClient(String mUsername, String mPassword) {
        super();
        this.mUsername = mUsername;
        this.mPassword = mPassword;
        String auth = this.mUsername + ":" + this.mPassword;
        mAuthorization = new String(Base64.encode(auth.getBytes(),
                Base64.DEFAULT));
        mAuthorization = mAuthorization.replace("\n", "");
    }

    public void setOnRtspListener(OnRtspListener listener) {
        mListener = listener;
    }

    private int getPort(String uri) {
        String port = uri.substring(uri.indexOf("//") + 2);
        port = port.substring(port.indexOf(":") + 1, port.indexOf("/"));
        return Integer.parseInt(port);
    }

    private String getHost(String uri) {
        String host = uri.substring(uri.indexOf("//") + 2);
        host = host.substring(0, host.indexOf(":"));
        return host;
    }

    public void start(String uri) {
        mUri = uri;
        try {
            mSocket = new Socket(getHost(uri), getPort(uri));
        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        new Thread(this).start();
    }

    public void doDescribe() {
        String content = String.format(DESCRIBE, mUri, mAuthorization);
        try {
            mSocket.getOutputStream().write(content.getBytes());
            // byte[] b = new byte[2048];
            // int length = mSocket.getInputStream().read(b);
            // String res = new String(b, 0, length);
            // Log.v("a", res);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    public void doSetup() {
        String content = String.format(SETUP, mUri, mAuthorization);
        try {
            mSocket.getOutputStream().write(content.getBytes());
            // byte[] b = new byte[2048];
            // int length = mSocket.getInputStream().read(b);
            // String res = new String(b, 0, length);
            // Log.v("a", res);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void doPlay() {
        String content = String.format(PLAY, mUri, mAuthorization);
        try {
            mSocket.getOutputStream().write(content.getBytes());
            // byte[] b = new byte[32];
            // Arrays.fill(b, (byte) 0);
            // InputStream is = mSocket.getInputStream();
            // int tmp, count = 0;
            // while ((tmp = is.read()) != -1) {
            // b[count] = (byte) tmp;
            // count++;
            // if (count == 32) {
            // Log.d("RTSP Stream", new String(b, 0, count));
            // count = 0;
            // Arrays.fill(b, (byte) 0);
            // }
            // }
            // String res = new String(b, 0, length);
            // res.trim();
            if (mListener != null) {
                mListener.OnRtspStartPlay(mUri);
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        doDescribe();
        doSetup();
        doPlay();
    }

}
