package com.dftc.onvif.finder;

import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.util.Xml;

import org.xmlpull.v1.XmlPullParser;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.Random;
import java.util.UUID;

public class HttpSoap {

    public static final String USERNAME = "admin";
    public static final String PASSWORD = "888888";

    public static final String DEVICE_UUID = "386d43c9-1787-49f8-bfb4-11280f7579d9";
    public static final String DEVICE_URL = "http://%s/onvif/device_service";

    public static final String GET_SUBSERVICE_POST = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GetServices xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><IncludeCapability>false</IncludeCapability></GetServices></s:Body></s:Envelope>";
    public static final String IS_NEED_AUTH = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GetClientCertificateMode xmlns=\"http://www.onvif.org/ver10/device/wsdl\"></GetClientCertificateMode></s:Body></s:Envelope>";
    public static final String GET_CAPABILITIES = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header><Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>%s</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">%s</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>All</Category></GetCapabilities></s:Body></s:Envelope>";
    public static final String GET_PROFILES = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><wsse:UsernameToken><wsse:Username>%s</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password><wsse:Nonce>%s</wsse:Nonce><wsu:Created>%s</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header><s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"></GetProfiles></s:Body></s:Envelope>";
    public static final String GET_PROFILE = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><wsse:UsernameToken><wsse:Username>%s</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password><wsse:Nonce>%s</wsse:Nonce><wsu:Created>%s</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header><s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GetProfile xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><ProfileToken>%s</ProfileToken></GetProfile></s:Body></s:Envelope>";
    public static final String CREATE_PROFILE_BODY = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><wsse:UsernameToken><wsse:Username>%s</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password><wsse:Nonce>%s</wsse:Nonce><wsu:Created>%s</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header><s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><CreateProfile xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><Name>%s</Name></CreateProfile></s:Body></s:Envelope>";
    public static final String GET_URI_BODY = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><wsse:UsernameToken><wsse:Username>%s</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password><wsse:Nonce>%s</wsse:Nonce><wsu:Created>%s</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header><s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><StreamSetup><Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream><Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport></StreamSetup><ProfileToken>%s</ProfileToken></GetStreamUri></s:Body></s:Envelope>";

    public static final String GET_SCREENSHOT = "<?xml version=\"1.0\" encoding=\"utf-8\"?> <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header><Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" s:mustUnderstand=\"1\"><UsernameToken><Username>%s</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">%s</Created></UsernameToken></Security></s:Header><s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GetSnapshotUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><ProfileToken>%s</ProfileToken></GetSnapshotUri></s:Body></s:Envelope>";

    public static final String XMIC_PROFILE = "xmic_profile";
    private HttpURLConnection mUrlConn;
    private CameraDevice mCamera;
    private String mCreated, mNonce, mAuthPwd;

    public HttpSoap() {
    }

    private void initConn(String cameraIP, Integer cameraPort, boolean mainRate) {
        String ipAddr = cameraIP;
        if (cameraPort != null)
            ipAddr += ":" + cameraPort;
        String url = String.format(DEVICE_URL, ipAddr);
        mCamera = new CameraDevice(UUID.fromString(DEVICE_UUID), url,
                mainRate);
        mCamera.setOnline(true);
        mCamera.setIpAddr(cameraIP);

        mCamera.setSecurity(USERNAME, PASSWORD);

        createAuthString();
    }

    private void createAuthString() {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'",
                Locale.CHINA);
        mCreated = df.format(new Date());
        mNonce = getNonce();
        mAuthPwd = getPasswordEncode(mNonce, mCamera.password, mCreated);
    }

    private void initConn(String url) {
        try {
            URL url1 = new URL(url);
            mUrlConn = (HttpURLConnection) url1.openConnection();
            mUrlConn.setDoInput(true);
            mUrlConn.setDoOutput(true);
            mUrlConn.setRequestMethod("POST");
            mUrlConn.setUseCaches(false);
            mUrlConn.setInstanceFollowRedirects(true);
            mUrlConn.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String inputStream2String(InputStream in) throws IOException {
        StringBuffer out = new StringBuffer();
        byte[] b = new byte[4096];
        for (int n; (n = in.read(b)) != -1; ) {
            out.append(new String(b, 0, n));
        }
        return out.toString();
    }

    public String getNonce() {
        String base = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 24; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }

    public String getPasswordEncode(String nonce, String password, String date) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            // 从官方文档可以知道我们nonce还需要用Base64解码一次
            byte[] b1 = Base64.decode(nonce.getBytes(), Base64.DEFAULT);
            // 生成字符字节流
            byte[] b2 = date.getBytes(); // "2013-09-17T09:13:35Z";
            byte[] b3 = password.getBytes();
            // 根据我们传得值的长度生成流的长度
            byte[] b4 = new byte[b1.length + b2.length + b3.length];
            // 利用sha-1加密字符
            md.update(b1, 0, b1.length);
            md.update(b2, 0, b2.length);
            md.update(b3, 0, b3.length);
            // 生成sha-1加密后的流
            b4 = md.digest();
            // 生成最终的加密字符串
            String result = new String(Base64.encode(b4, Base64.DEFAULT));
            return result.replace("\n", "");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public CameraDevice cameraDevice(String cameraIP, Integer cameraPort, boolean mainRate) {
        initConn(cameraIP, cameraPort, mainRate);
        try {
            // =========获取子服务=========
            initConn(mCamera.serviceURL);
            mUrlConn.connect();
            String content = String.format(GET_CAPABILITIES, mCamera.username,
                    mAuthPwd, mNonce, mCreated);
            mUrlConn.getOutputStream().write(content.getBytes());
            InputStream inStream = mUrlConn.getInputStream();
            String res = inputStream2String(inStream);
            String mediaUrl = findMediaServiceUrl(res);

            mUrlConn.disconnect();// add
            // =========获取Profile=========
            initConn(mediaUrl);
            mUrlConn.connect();
            content = String.format(GET_PROFILES, mCamera.username, mAuthPwd,
                    mNonce, mCreated);
            mUrlConn.getOutputStream().write(content.getBytes());
            inStream = mUrlConn.getInputStream();
            res = inputStream2String(inStream);
            String profile = getOldProfileToken(res);
            /*
             * if (profile.isEmpty()) { //=========创建Profile=========
             * initConn(mediaUrl); mUrlConn.connect(); content =
             * String.format(CREATE_PROFILE_BODY, mCamera.username, mAuthPwd,
             * mNonce, mCreated, XMIC_PROFILE);
             * mUrlConn.getOutputStream().write(content.getBytes()); inStream =
             * mUrlConn.getInputStream(); res = inputStream2String(inStream);
             * profile = getProfileToken(res); }
             */
            mUrlConn.disconnect();// add
            // =========读取RTSP的配置信息====
            initConn(mediaUrl);
            mUrlConn.connect();
            content = String.format(GET_PROFILE, mCamera.username, mAuthPwd,
                    mNonce, mCreated, profile);
            mUrlConn.getOutputStream().write(content.getBytes());
            inStream = mUrlConn.getInputStream();
            res = inputStream2String(inStream);
            analyseVideoEncoderConfiguration(res);
            // =========配置RTSP==============
            mUrlConn.disconnect();// add
            // =========获取RTSP的URI=========
            // String uri = null;
            initConn(mediaUrl);
            mUrlConn.connect();
            content = getURIContent(profile);
            mUrlConn.getOutputStream().write(content.getBytes());
            inStream = mUrlConn.getInputStream();
            res = inputStream2String(inStream);
            String uri = getStreamURI(res);
            mUrlConn.disconnect();// add
            // =========获取RTSP的截图=========
            try {
                initConn(mediaUrl);
                mUrlConn.connect();
                content = String.format(GET_SCREENSHOT, mCamera.username,
                        mAuthPwd, mNonce, mCreated, profile);
                mUrlConn.getOutputStream().write(content.getBytes());
                inStream = mUrlConn.getInputStream();
                res = inputStream2String(inStream);
                String snapshotUri = getSnapshotUri(res);
                if (!TextUtils.isEmpty(snapshotUri))
                    mCamera.setSnapshotUri(snapshotUri);
                Log.d("HttpSoap", "snapshotUri:" + snapshotUri);
                // writeTXT(new File("/sdcard/log_SCREENSHOT.xml"), res);
            } catch (Exception e) {
                e.printStackTrace();
            }
            // =========获取RTSP的URI=========

            mCamera.setRtspUrl(uri.substring(0, uri.indexOf("//") + 2)
                    + mCamera.username + ":" + mCamera.password + "@"
                    + uri.substring(uri.indexOf("//") + 2));

            mCamera.initId();
            return mCamera;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void analyseVideoEncoderConfiguration(String xml) {
        Log.d("xqq", "analyseVideoEncoderConfiguration xml:" + xml);
        writeTXT(new File("/sdcard/log_analyseVideoEncoderConfiguration.xml"),
                xml);
        XmlPullParser parser = Xml.newPullParser();
        InputStream input = new ByteArrayInputStream(xml.getBytes());
        try {
            parser.setInput(input, "UTF-8");
            int eventType = parser.getEventType();
            boolean done = false;
            while (eventType != XmlPullParser.END_DOCUMENT || done) {
                switch (eventType) {
                    case XmlPullParser.START_DOCUMENT:
                        break;
                    case XmlPullParser.START_TAG:
                        if (parser.getName().equals("Width")) {
                            eventType = parser.next();
                            mCamera.width = Integer.parseInt(parser.getText());
                        } else if (parser.getName().equals("Height")) {
                            eventType = parser.next();
                            mCamera.height = Integer.parseInt(parser.getText());
                        } else if (parser.getName().equals("FrameRateLimit")) {
                            eventType = parser.next();
                            mCamera.rate = Integer.parseInt(parser.getText());
                        }
                        break;
                    case XmlPullParser.END_TAG:
                        break;
                    default:
                        break;
                }
                eventType = parser.next();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getURIContent(String profile) {
        String content = String.format(GET_URI_BODY, mCamera.username,
                mAuthPwd, mNonce, mCreated, profile);
        return content;
    }

    private String findMediaServiceUrl(String xml) {
        Log.d("xqq", "findMediaServiceUrl xml:" + xml);
        writeTXT(new File("/sdcard/log_findMediaServiceUrl.xml"), xml);
        XmlPullParser parser = Xml.newPullParser();
        InputStream input = new ByteArrayInputStream(xml.getBytes());
        try {
            parser.setInput(input, "UTF-8");
            int eventType = parser.getEventType();
            boolean done = false;
            while (eventType != XmlPullParser.END_DOCUMENT || done) {
                switch (eventType) {
                    case XmlPullParser.START_DOCUMENT:
                        break;
                    case XmlPullParser.START_TAG:
                        if (parser.getName().equals("Media")) {
                            eventType = parser.next();
                            if (parser.getName().equals("XAddr")) {
                                eventType = parser.next();
                                if (!parser.getText().isEmpty()) {
                                    return parser.getText();
                                }
                            }

                        }
                        break;
                    case XmlPullParser.END_TAG:
                        break;
                    default:
                        break;
                }
                eventType = parser.next();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private String getOldProfileToken(String xml) {
        Log.d("xqq", "getOldProfileToken xml:" + xml);
        writeTXT(new File("/sdcard/log_getOldProfileToken.xml"), xml);
        XmlPullParser parser = Xml.newPullParser();
        ArrayList<TProfile> profiles = new ArrayList<TProfile>();
        InputStream input = new ByteArrayInputStream(xml.getBytes());
        try {
            parser.setInput(input, "UTF-8");
            int eventType = parser.getEventType();
            boolean done = false;
            while (eventType != XmlPullParser.END_DOCUMENT || done) {
                switch (eventType) {
                    case XmlPullParser.START_DOCUMENT:
                        break;
                    case XmlPullParser.START_TAG:
                        if (parser.getName().equals("Profiles")) {
                            String token = parser.getAttributeValue(null, "token");
                            TProfile profile = new TProfile(token);
                            while (!(eventType == XmlPullParser.START_TAG && parser
                                    .getName().equals("Resolution"))) {
                                eventType = parser.next();
                            }
                            while (!(eventType == XmlPullParser.START_TAG && parser
                                    .getName().equals("Width"))) {
                                eventType = parser.next();
                            }
                            parser.next();
                            profile.width = Integer.parseInt(parser.getText());
                            profiles.add(profile);
                        }
                        break;
                    case XmlPullParser.END_TAG:
                        break;
                    default:
                        break;
                }
                eventType = parser.next();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (profiles.size() > 0) {
            TProfile tmpProfile = profiles.get(0);
            Log.d("xqq", "getOldProfileToken width:" + tmpProfile.width
                    + " height:" + tmpProfile.height);
            for (int i = 1; i < profiles.size(); i++) {
                Log.d("xqq", "getOldProfileToken width:"
                        + profiles.get(i).width + " height:"
                        + profiles.get(i).height);
                if (mCamera.isMainRate()) {
                    if (tmpProfile.width < profiles.get(i).width) {
                        tmpProfile = profiles.get(i);
                    }
                } else {
                    if (tmpProfile.width > profiles.get(i).width) {
                        tmpProfile = profiles.get(i);
                    }
                }

            }
            return tmpProfile.token;
        } else {
            return "";
        }
    }

    private String getStreamURI(String xml) {
        XmlPullParser parser = Xml.newPullParser();
        InputStream input = new ByteArrayInputStream(xml.getBytes());
        try {
            parser.setInput(input, "UTF-8");
            int eventType = parser.getEventType();
            boolean done = false;
            while (eventType != XmlPullParser.END_DOCUMENT || done) {
                switch (eventType) {
                    case XmlPullParser.START_DOCUMENT:
                        break;
                    case XmlPullParser.START_TAG:
                        if (parser.getName().equals("Uri")) {
                            eventType = parser.next();
                            return parser.getText();
                        }
                        break;
                    case XmlPullParser.END_TAG:

                        break;
                    default:
                        break;
                }
                eventType = parser.next();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private String getSnapshotUri(String xml) {
        XmlPullParser parser = Xml.newPullParser();
        InputStream input = new ByteArrayInputStream(xml.getBytes());
        try {
            parser.setInput(input, "UTF-8");
            int eventType = parser.getEventType();
            boolean done = false;
            while (eventType != XmlPullParser.END_DOCUMENT || done) {
                switch (eventType) {
                    case XmlPullParser.START_DOCUMENT:
                        break;
                    case XmlPullParser.START_TAG:
                        if (parser.getName().equals("Uri")) {
                            eventType = parser.next();
                            return parser.getText();
                        }
                        break;
                    case XmlPullParser.END_TAG:
                        break;
                    default:
                        break;
                }
                eventType = parser.next();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public boolean writeTXT(File f, String str) {

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(f, false);
        } catch (FileNotFoundException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }

        byte[] bytes;
        try {
            bytes = str.getBytes("UTF-8");

            try {
                fos.write(bytes);
                return true;
            } catch (IOException e) {
                e.printStackTrace();
            }

        } catch (UnsupportedEncodingException e1) {
            e1.printStackTrace();
        }

        try {
            fos.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return false;
    }

    class TProfile {
        public String token;
        public int width;
        public int height;
        public int FrameRateLimit;

        public TProfile(String token) {
            this.token = token;
        }
    }
}
