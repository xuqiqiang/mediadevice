package com.dftc.baseview;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView.OnEditorActionListener;

public class CustomEditText extends LinearLayout {
	
	private Context context;
	private EditText mEditText;
	private View mErrorTip;
	private boolean onTop = true;
	

	public CustomEditText(Context context, AttributeSet attributeSet) {
		super(context, attributeSet);
		this.context = context;
		LayoutInflater mInflater = LayoutInflater.from(context);
        View view = mInflater.inflate(R.layout.custom_edittext, null);
        this.addView(view);
        
        mEditText = (EditText) (view.findViewById(R.id.edittext));
        mErrorTip = view.findViewById(R.id.iv_error_tip);
        
        TypedArray attrs = context.obtainStyledAttributes(attributeSet,
                R.styleable.CustomEditText, 0, 0);
        
        int mlayoutHeight = attrs
        		.getDimensionPixelSize(R.styleable.CustomEditText_fab_layout_height, -1);
        
        if(mlayoutHeight != -1){
        	RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) mEditText.getLayoutParams();  
            params.height = mlayoutHeight;  
            mEditText.setLayoutParams(params); 
        }

        boolean isPassword = attrs.getBoolean(R.styleable.CustomEditText_fab_isPassword, false);
        if(isPassword){
        	mEditText.setFilters(new InputFilter[]{new InputFilter.LengthFilter(20)});
        	mEditText.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        	CheckBox switch_eye = (CheckBox) (view.findViewById(R.id.switch_eye));
        	switch_eye.setVisibility(View.VISIBLE);
        	
        	switch_eye.setOnCheckedChangeListener(new OnCheckedChangeListener() {

    			@Override
    			public void onCheckedChanged(CompoundButton buttonView,
    					boolean isChecked) {
    				int selection = mEditText.getSelectionStart();
    				if(isChecked){
    					mEditText.setInputType(InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
    				}
    				else{
    					mEditText.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
    				}
    				mEditText.setSelection(selection);
    			}

    		});
        }
        
        String mHint = attrs.getString(R.styleable.CustomEditText_fab_hint);
        if(!TextUtils.isEmpty(mHint)){
        	mEditText.setHint(mHint);
        }

        int mImeAction = attrs.getInt(R.styleable.CustomEditText_fab_imeAction, 0);
        if(mImeAction == 1){
        	mEditText.setImeOptions(EditorInfo.IME_ACTION_NEXT);
        }
        else if(mImeAction == 2){
        	mEditText.setImeOptions(EditorInfo.IME_ACTION_GO);
        }
        
        int mDrawable = attrs
                .getResourceId(R.styleable.CustomEditText_fab_drawable, 0);
        int mDrawablePadding = attrs
        		.getDimensionPixelSize(R.styleable.CustomEditText_fab_drawablePadding, 0);
        if (mDrawable != 0) {
        	Drawable drawable= getResources().getDrawable(mDrawable);
        	/// è¿™ä¸€æ­¥å¿…é¡»è¦�å�š,å�¦åˆ™ä¸�ä¼šæ˜¾ç¤º.
        	drawable.setBounds(0, 0, drawable.getMinimumWidth(), drawable.getMinimumHeight());
        	mEditText.setCompoundDrawables(drawable,null,null,null);
        	mEditText.setCompoundDrawablePadding(mDrawablePadding);
        }
        
        setOnTop(attrs.getBoolean(R.styleable.CustomEditText_fab_onTop, true));
        
        attrs.recycle();
        
        mEditText.addTextChangedListener(new TextWatcher() {

            @Override
            public void onTextChanged(CharSequence s, int start, int before,
                    int count) {
            	dismissPopupPrompt();
            }

            @Override
            public void afterTextChanged(Editable arg0) {
            }

            @Override
            public void beforeTextChanged(CharSequence s, int start, int count,
                    int after) {
            }
        });
        
        
        
	}
	
	public Editable getText(){
		return mEditText.getText();
	}
	
	public void setText(CharSequence text){
		mEditText.setText(text);
	}
	
	public void setHint(String hint){
		mEditText.setHint(hint);
	}
	
	public CharSequence getHint(){
		return mEditText.getHint();
	}
	
	public void setOnEditorActionListener(OnEditorActionListener listener){
		mEditText.setOnEditorActionListener(listener);
	}

	public static void changeBackground(View view, int resId) {
        if (view != null) {
            int paddingLeft = view.getPaddingLeft();
            int paddingTop = view.getPaddingTop();
            int paddingRight = view.getPaddingRight();
            int paddingBottom = view.getPaddingBottom();
            view.setBackgroundResource(resId);
            view.setPadding(paddingLeft, paddingTop, paddingRight, paddingBottom);
        }
    }
	
	private PopupPromptView mPopupPromptView;

    public void setOnTop(boolean onTop) {
    	this.onTop = onTop;
    }
    
    public void showPopupPrompt(String message){
    	
    	changeBackground(mEditText, R.drawable.custom_edittext_bg_error);

    	if(mPopupPromptView == null)
    		mPopupPromptView = new PopupPromptView(context);
    	
    	mPopupPromptView.setText(message);
    	mErrorTip.setVisibility(View.VISIBLE);

    	mPopupPromptView.showPop(mErrorTip, onTop);
    }
    
    public void showPopupPrompt(int resId){
    	showPopupPrompt(context.getString(resId));
    }
    
    public void dismissPopupPrompt(){
    	if(mPopupPromptView != null
    			&& mPopupPromptView.isShowing()){
    		mPopupPromptView.dismiss();
	    	changeBackground(mEditText, R.drawable.custom_edittext_bg);
			mErrorTip.setVisibility(View.GONE);
    	}
    }
    
}