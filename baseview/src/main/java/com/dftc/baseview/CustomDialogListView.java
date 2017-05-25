package com.dftc.baseview;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.ListView;

public class CustomDialogListView extends ListView {
    private static final int MAX_WIDTH_PX = 300;
    private static final int MAX_HEIGHT_PX = 400;
    private Context context;

    public CustomDialogListView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.context = context;
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        // super.onMeasure(widthMeasureSpec, heightMeasureSpec );
        super.onMeasure(widthMeasureSpec, MeasureSpec.makeMeasureSpec(
                (int) DisplayUtils.dip2px(context, MAX_HEIGHT_PX),
                MeasureSpec.AT_MOST));

    }
}