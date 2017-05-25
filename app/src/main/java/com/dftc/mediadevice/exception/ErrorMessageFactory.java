/**
 * Copyright (C) 2015 Fernando Cejas Open Source Project
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dftc.mediadevice.exception;

import android.content.Context;

import com.dftc.mediadevice.R;
import com.dftc.mediadevice.data.exception.CameraConnectException;
import com.dftc.mediadevice.data.exception.CameraDisconnectException;
import com.dftc.mediadevice.data.exception.CameraNotFoundException;
import com.dftc.mediadevice.data.exception.NetworkConnectionException;
import com.dftc.mediadevice.data.exception.RtmpServerConnectException;


/**
 * Factory used to create error messages from an Exception as a condition.
 */
public class ErrorMessageFactory {

    private ErrorMessageFactory() {
        //empty
    }

    /**
     * Creates a String representing an error message.
     *
     * @param context   Context needed to retrieve string resources.
     * @param exception An exception used as a condition to retrieve the correct error message.
     * @return {@link String} an error message.
     */
    public static String create(Context context, Exception exception) {
        String message = context.getString(R.string.exception_message_generic);

        if (exception instanceof NetworkConnectionException) {
            message = context.getString(R.string.exception_message_no_connection);
        } else if (exception instanceof CameraNotFoundException) {
            message = context.getString(R.string.exception_message_camera_not_found);
        } else if (exception instanceof CameraConnectException) {
            message = "摄像头连接出错";
        } else if (exception instanceof CameraDisconnectException) {
            message = "摄像头已断开";
        } else if (exception instanceof RtmpServerConnectException) {
            message = "RTMP服务器连接已断开";
        }

        return message;
    }
}
