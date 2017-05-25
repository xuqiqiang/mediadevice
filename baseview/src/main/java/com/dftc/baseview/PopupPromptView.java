package com.dftc.baseview;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.annotation.TargetApi;
import android.content.Context;
import android.graphics.Color;
import android.os.Build;
import android.os.Handler;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnTouchListener;
import android.view.ViewGroup;
import android.view.ViewTreeObserver.OnPreDrawListener;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.PopupWindow.OnDismissListener;
import android.widget.TextView;


public class PopupPromptView {
    private static final String TAG = "PopupPrompt";
    private PopupWindow mPopupWindow;
    private View popup_window_layout;
    private ViewGroup popup_window_content;
    private Context context;
    private boolean isPopupShowing;

    public PopupPromptView(Context context) {
        this.context = context;
        initView();
    }

    private void initView() {
        this.mPopupWindow = new PopupWindow(this.context);
        this.mPopupWindow.setTouchInterceptor(new OnTouchListener() {

            @Override
            public boolean onTouch(View v, MotionEvent event) {
                if (event.getAction() == MotionEvent.ACTION_OUTSIDE) {
                    mPopupWindow.dismiss();
                }
                return false;
            }

        });
        this.mPopupWindow.setWidth(LinearLayout.LayoutParams.WRAP_CONTENT);
        this.mPopupWindow.setHeight(LinearLayout.LayoutParams.WRAP_CONTENT);
        this.mPopupWindow.setFocusable(false);
        this.mPopupWindow.setTouchable(true);
        this.mPopupWindow.setOutsideTouchable(false);

        initPopupWindowLayout();
    }

    public void setText(String text) {
        TextView popup_window_content_text = new TextView(context);
        popup_window_content_text.setGravity(Gravity.CENTER);
        popup_window_content_text.setTextColor(Color.WHITE);

        popup_window_content_text.setText(text);

        popup_window_content.removeAllViews();
        popup_window_content.addView(popup_window_content_text);
    }

    public void setText(int resId) {
        setText(context.getString(resId));
    }

    private void initPopupWindowLayout() {
        LayoutInflater mInflater = LayoutInflater.from(context);
        this.popup_window_layout = (LinearLayout) mInflater.inflate(R.layout.popup_menu_prompt_layout, null);
        popup_window_content = (ViewGroup) popup_window_layout.findViewById(R.id.popup_window_content);
        this.mPopupWindow.setBackgroundDrawable(null);
        this.mPopupWindow.setContentView(popup_window_layout);
    }

    public void setOnDismissListener(OnDismissListener onDismissListener) {
        this.mPopupWindow.setOnDismissListener(onDismissListener);
    }

    public void dismiss() {
        if (isPopupShowing) {
            isPopupShowing = false;
            try {
                if (mPopupWindow.isShowing())
                    mPopupWindow.dismiss();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public boolean isShowing() {
        return isPopupShowing;//mPopupWindow.isShowing();
    }

    private OnPreDrawListener onPreDrawListener;

    public void showPop(final View view, final boolean onTop) {
        if (view != null) {

            onPreDrawListener = new OnPreDrawListener() {

                public boolean onPreDraw() {
                    popup_window_layout.measure(LinearLayout.LayoutParams.WRAP_CONTENT,
                            LinearLayout.LayoutParams.WRAP_CONTENT);
                    int xoff = -popup_window_layout.getMeasuredWidth()
                            + view.getWidth() / 2
                            + (int) DisplayUtils.dip2px(context, 32);
                    int yoff;
                    if (onTop) {
                        popup_window_content.setBackgroundResource(R.drawable.tip_bottom_bg);
                        yoff = -view.getHeight() - popup_window_layout.getMeasuredHeight()
                                + (int) DisplayUtils.dip2px(context, 4);
                    } else {
                        popup_window_content.setBackgroundResource(R.drawable.tip_top_bg);
                        yoff = -(int) DisplayUtils.dip2px(context, 4);
                    }
                    dismiss();
                    try {
                        //this.mPopupWindow.showAtLocation(view, 51, measuredWidth, measuredHeight);
                        mPopupWindow.showAsDropDown(view,
                                xoff, yoff
                        );
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    view.getViewTreeObserver().removeOnPreDrawListener(onPreDrawListener);
                    isPopupShowing = true;
                    return true;
                }
            };

            view.getViewTreeObserver().addOnPreDrawListener(onPreDrawListener);
        }
    }

    public static void show(Context context, int resId, final View view, final boolean onTop) {
        show(context, context.getString(resId), view, onTop);
    }

    public static void show(Context context, String message, final View view, final boolean onTop) {
        final PopupPromptView mPopupPromptView = new PopupPromptView(context);

        mPopupPromptView.setText(message);

        mPopupPromptView.showPop(view, onTop);

        new Handler().postDelayed(new Runnable() {

            @Override
            public void run() {

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.HONEYCOMB) {
                    mPopupPromptView.dismissDelay();
                } else {
                    mPopupPromptView.dismiss();
                }

            }

        }, 2000);
    }

    private static final int HIDDEN_DURATION = 1000;

    @TargetApi(Build.VERSION_CODES.HONEYCOMB)
    public void dismissDelay() {
        ObjectAnimator hiddenNewButtonAnimator = ObjectAnimator
                .ofFloat(popup_window_layout, "alpha", 1, 0);
        AnimatorSet mAnimation = new AnimatorSet()
                .setDuration(HIDDEN_DURATION);
        mAnimation.play(
                hiddenNewButtonAnimator);
        mAnimation.start();

        new Handler().postDelayed(new Runnable() {

            @Override
            public void run() {

                dismiss();
            }

        }, HIDDEN_DURATION);

    }
}
