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
package com.dftc.mediadevice.data.mapper;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.support.annotation.NonNull;

import com.dftc.libonvif.model.CameraInfomation;
import com.dftc.mediadevice.data.utils.DisplayUtils;
import com.dftc.mediadevice.domain.Camera;

import java.io.File;

import javax.inject.Inject;
import javax.inject.Singleton;

/**
 * Mapper class used to transform {@link CameraInfomation} (in the data layer) to {@link Camera} in the
 * domain layer.
 */
@Singleton
public class CameraScreenshotFileMapper {

    private final Context context;
    @Inject
    CameraScreenshotFileMapper(@NonNull Context context) {
        this.context = context.getApplicationContext();
    }

    public Bitmap transform(File file) {

        Bitmap bitmap = null;
        BitmapFactory.Options op = new BitmapFactory.Options();
        op.inJustDecodeBounds = true;
        float dw = DisplayUtils.dip2px(context, 100);
        float dh = DisplayUtils.dip2px(context, 100);

        bitmap = BitmapFactory.decodeFile(file.getPath(), op);
        float wRatio = (float) Math.ceil(op.outWidth / dw);
        float hRatio = (float) Math.ceil(op.outHeight / dh);
        if (wRatio > 1 || hRatio > 1) {
            op.inSampleSize = (int) Math.max(wRatio, hRatio);
        }
        op.inJustDecodeBounds = false;
        try {
            bitmap = BitmapFactory.decodeFile(file.getPath(), op);
        } catch (Exception e) {
            e.printStackTrace();
        } catch (OutOfMemoryError e) {
            e.printStackTrace();
        }

        return bitmap;
    }

}
