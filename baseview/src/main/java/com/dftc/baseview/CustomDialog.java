package com.dftc.baseview;

import java.util.ArrayList;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.text.method.ScrollingMovementMethod;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

public class CustomDialog extends Dialog {

    public CustomDialog(Context context, int theme) {
        super(context, theme);
    }

    public CustomDialog(Context context) {
        super(context);
    }

    /**
     * Helper class for creating a custom dialog
     */
    public static class Builder {
        private static final int SELECT_NO = -99;
        private Context context = null;
        private int iconId = -1;
        private String title = null;
        private String message = null;
        private String[] items = null;
        private int[] itemsDrawable = null;
        private int oldSelect = SELECT_NO;
        private String positiveButtonText = null;
        private String negativeButtonText = null;
        private String extraButtonText = null;
        private boolean cancelable = true;
        private View contentView;
        private View layout;

        private DialogInterface.OnClickListener itemsClickListener,
                positiveButtonClickListener, negativeButtonClickListener,
                extraButtonClickListener, onKeyBackListener;

        public Builder(Context context) {
            this.context = context;
        }

        /**
         * Set the Dialog icon from iconId
         *
         * @param iconId
         * @return
         */
        public Builder setIcon(int iconId) {
            this.iconId = iconId;
            return this;
        }

        /**
         * Set the Dialog message from String
         *
         * @param title
         * @return
         */
        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        /**
         * Set the Dialog message from resource
         *
         * @param title
         * @return
         */
        public Builder setMessage(int message) {
            this.message = (String) context.getText(message);
            return this;
        }

        /**
         * Set the Dialog items from String
         *
         * @param items & listener
         * @return
         */
        public Builder setItems(int items,
                                DialogInterface.OnClickListener itemsClickListener) {
            this.items = context.getResources().getStringArray(items);
            this.itemsClickListener = itemsClickListener;
            return this;
        }

        /**
         * Set the Dialog items from String
         *
         * @param items & listener
         * @return
         */
        public Builder setItems(String[] items,
                                DialogInterface.OnClickListener itemsClickListener) {
            this.items = items;
            this.itemsClickListener = itemsClickListener;
            return this;
        }

        /**
         * Set the Dialog items from String
         *
         * @param items & listener
         * @return
         */
        public Builder setItems(ArrayList<String> items,
                                DialogInterface.OnClickListener itemsClickListener) {
            if (items != null)
                this.items = items.toArray(new String[0]);
            this.itemsClickListener = itemsClickListener;
            return this;
        }

        /**
         * Set the Dialog items from String
         *
         * @param items & oldSelect & listener
         * @return
         */
        public Builder setItems(String[] items, int oldSelect,
                                DialogInterface.OnClickListener itemsClickListener) {
            this.items = items;
            this.oldSelect = oldSelect;
            this.itemsClickListener = itemsClickListener;
            return this;
        }

        /**
         * Set the Dialog items from String
         *
         * @param items & oldSelect & listener
         * @return
         */
        public Builder setItems(ArrayList<String> items, int oldSelect,
                                DialogInterface.OnClickListener itemsClickListener) {
            if (items != null)
                this.items = items.toArray(new String[0]);
            this.oldSelect = oldSelect;
            this.itemsClickListener = itemsClickListener;
            return this;
        }

        /**
         * Set the Dialog items from String
         *
         * @param items & oldSelect & listener
         * @return
         */
        public Builder setItems(int items, int oldSelect,
                                DialogInterface.OnClickListener itemsClickListener) {
            this.items = context.getResources().getStringArray(items);
            this.oldSelect = oldSelect;
            this.itemsClickListener = itemsClickListener;
            return this;
        }

        /**
         * Set the Dialog itemsDrawable
         *
         * @param itemsDrawable & listener
         * @return
         */
        public Builder setItemsDrawable(int[] itemsDrawable) {
            this.itemsDrawable = itemsDrawable;
            return this;
        }

        /**
         * Set the Dialog title from resource
         *
         * @param title
         * @return
         */
        public Builder setTitle(int title) {
            this.title = (String) context.getText(title);
            return this;
        }

        /**
         * Set the Dialog title from String
         *
         * @param title
         * @return
         */
        public Builder setTitle(String title) {
            this.title = title;
            return this;
        }

        /**
         * Set a custom content view for the Dialog. If a message is set, the
         * contentView is not added to the Dialog...
         *
         * @param v
         * @return
         */
        public Builder setContentView(View v) {
            this.contentView = v;
            return this;
        }

        /**
         * Set the positive button resource and it's listener
         *
         * @param positiveButtonText
         * @param listener
         * @return
         */
        public Builder setPositiveButton(int positiveButtonText,
                                         DialogInterface.OnClickListener listener) {
            this.positiveButtonText = (String) context
                    .getText(positiveButtonText);
            if (listener != null)
                this.positiveButtonClickListener = listener;
            else {
                this.positiveButtonClickListener = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.cancel();
                    }
                };
            }
            return this;
        }

        /**
         * Set the positive button text and it's listener
         *
         * @param positiveButtonText
         * @param listener
         * @return
         */
        public Builder setPositiveButton(String positiveButtonText,
                                         DialogInterface.OnClickListener listener) {
            this.positiveButtonText = positiveButtonText;
            // this.positiveButtonClickListener = listener;

            if (listener != null)
                this.positiveButtonClickListener = listener;
            else {
                this.positiveButtonClickListener = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.cancel();
                    }
                };
            }

            return this;
        }

        /**
         * Set the negative button resource and it's listener
         *
         * @param negativeButtonText
         * @param listener
         * @return
         */
        public Builder setNegativeButton(int negativeButtonText,
                                         DialogInterface.OnClickListener listener) {
            this.negativeButtonText = (String) context
                    .getText(negativeButtonText);
            // this.negativeButtonClickListener = listener;

            if (listener != null)
                this.negativeButtonClickListener = listener;
            else {
                this.negativeButtonClickListener = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.cancel();
                    }
                };
            }
            return this;
        }

        /**
         * Set the negative button text and it's listener
         *
         * @param negativeButtonText
         * @param listener
         * @return
         */
        public Builder setNegativeButton(String negativeButtonText,
                                         DialogInterface.OnClickListener listener) {
            this.negativeButtonText = negativeButtonText;
            if (listener != null)
                this.negativeButtonClickListener = listener;
            else {
                this.negativeButtonClickListener = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.cancel();
                    }
                };
            }
            return this;
        }

        public Builder setExtraButton(int extraButtonText,
                                      DialogInterface.OnClickListener listener) {
            this.extraButtonText = (String) context.getText(extraButtonText);

            if (listener != null)
                this.extraButtonClickListener = listener;
            else {
                this.extraButtonClickListener = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.cancel();
                    }
                };
            }
            return this;
        }

        public Builder setExtraButton(String extraButtonText,
                                      DialogInterface.OnClickListener listener) {
            this.extraButtonText = extraButtonText;
            // this.extraButtonClickListener = listener;

            if (listener != null)
                this.extraButtonClickListener = listener;
            else {
                this.extraButtonClickListener = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.cancel();
                    }
                };
            }
            return this;
        }

        public Builder setOnKeyBackListener(
                DialogInterface.OnClickListener listener) {
            this.onKeyBackListener = listener;
            return this;
        }

        /**
         * Set the Dialog cancelable
         *
         * @param cancelable
         * @return
         */
        public Builder setCancelable(boolean cancelable) {
            this.cancelable = cancelable;
            return this;
        }

        /**
         * Get the Dialog View
         *
         * @param null
         * @return
         */
        public View getView() {
            return layout;
        }

        /**
         * Create the custom dialog
         */
        public CustomDialog create() {
            LayoutInflater inflater = (LayoutInflater) context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            // instantiate the dialog with the custom Theme
            final CustomDialog dialog = new CustomDialog(context,
                    R.style.CustomDialog);
            dialog.setCancelable(cancelable);
            dialog.setCanceledOnTouchOutside(false);
            // View layout = inflater.inflate(R.layout.custom_dialog_layout,
            // null);
            layout = inflater.inflate(R.layout.custom_dialog_layout, null);
            dialog.addContentView(layout, new LayoutParams(
                    LayoutParams.FILL_PARENT, LayoutParams.WRAP_CONTENT));
            // set the dialog title
            ((TextView) layout.findViewById(R.id.title)).setText(title);
            // set the confirm button
            if (positiveButtonText != null) {
                layout.findViewById(R.id.positiveButton).setVisibility(
                        View.VISIBLE);
                ((Button) layout.findViewById(R.id.positiveButton))
                        .setText(positiveButtonText);
                if (positiveButtonClickListener != null) {
                    ((Button) layout.findViewById(R.id.positiveButton))
                            .setOnClickListener(new View.OnClickListener() {
                                public void onClick(View v) {
                                    positiveButtonClickListener.onClick(dialog,
                                            DialogInterface.BUTTON_POSITIVE);
                                }
                            });
                }
            } else {
                // if no confirm button just set the visibility to GONE
                layout.findViewById(R.id.positiveButton).setVisibility(
                        View.GONE);
            }
            // set the cancel button
            if (negativeButtonText != null) {
                layout.findViewById(R.id.negativeButton).setVisibility(
                        View.VISIBLE);
                ((Button) layout.findViewById(R.id.negativeButton))
                        .setText(negativeButtonText);
                if (negativeButtonClickListener != null) {
                    ((Button) layout.findViewById(R.id.negativeButton))
                            .setOnClickListener(new View.OnClickListener() {
                                public void onClick(View v) {
                                    negativeButtonClickListener.onClick(dialog,
                                            DialogInterface.BUTTON_NEGATIVE);
                                }
                            });
                }
            } else {
                // if no confirm button just set the visibility to GONE
                layout.findViewById(R.id.negativeButton).setVisibility(
                        View.GONE);
            }

            if (extraButtonText != null) {

                layout.findViewById(R.id.extraButton).setVisibility(
                        View.VISIBLE);
                ((Button) layout.findViewById(R.id.extraButton))
                        .setText(extraButtonText);
                if (extraButtonClickListener != null) {
                    ((Button) layout.findViewById(R.id.extraButton))
                            .setOnClickListener(new View.OnClickListener() {
                                public void onClick(View v) {
                                    extraButtonClickListener.onClick(dialog,
                                            DialogInterface.BUTTON_NEUTRAL);
                                }
                            });
                }
            } else {
                // if no confirm button just set the visibility to GONE
                layout.findViewById(R.id.extraButton).setVisibility(View.GONE);
            }
            dialog.setOnKeyListener(new OnKeyListener() {

                @Override
                public boolean onKey(DialogInterface dialog, int keyCode,
                                     KeyEvent event) {
                    if (keyCode == KeyEvent.KEYCODE_BACK) {
                        if (onKeyBackListener != null) {
                            onKeyBackListener.onClick(dialog,
                                    DialogInterface.BUTTON_NEGATIVE);
                            return true;
                        }
                    }
                    return false;
                }

            });

            if (iconId != -1) {
                ImageView iv_icon = (ImageView) layout.findViewById(R.id.icon);
                iv_icon.setImageResource(iconId);
            }
            // set the content message
            if (message != null) {
                TextView tv = (TextView) layout.findViewById(R.id.message);
                tv.setMovementMethod(ScrollingMovementMethod.getInstance());
                tv.setText(message);
            } else if (items != null) {
                TextView tv = (TextView) layout.findViewById(R.id.message);
                tv.setVisibility(View.GONE);
                final ListView lv = (ListView) layout
                        .findViewById(R.id.select_list);
                lv.setVisibility(View.VISIBLE);
                // lv.setLayoutParams(new
                // LinearLayout.LayoutParams(lv.getWidth(), 600));

                if (oldSelect == SELECT_NO) {
                    // ArrayAdapter<String> arrayAdapter = new
                    // ArrayAdapter<String>(
                    // context, R.layout.custom_dialog_list_item, items);
                    lv.setAdapter(new ListAdapter(false));
                    lv.setOnItemClickListener(new OnItemClickListener() {

                        @Override
                        public void onItemClick(AdapterView<?> arg0, View arg1,
                                                int position, long arg3) {
                            itemsClickListener.onClick(dialog, position);
                        }
                    });
                } else {
                    /*
                     * ArrayAdapter<String> arrayAdapter = new
                     * ArrayAdapter<String>( context,
                     * R.layout.custom_dialog_list_item_single_choice, items);
                     */
                    lv.setAdapter(new ListAdapter(true));
                    lv.setOnItemClickListener(new OnItemClickListener() {

                        @Override
                        public void onItemClick(AdapterView<?> arg0, View arg1,
                                                int position, long arg3) {
                            lv.setItemChecked(position, true);
                            itemsClickListener.onClick(dialog, position);
                        }
                    });
                    lv.setChoiceMode(ListView.CHOICE_MODE_SINGLE);
                    lv.setItemChecked(oldSelect, true);
                    lv.setSelection(oldSelect);
                }

            } else if (contentView != null) {
                // if no message set
                // add the contentView to the dialog body
                ((LinearLayout) layout.findViewById(R.id.content))
                        .removeAllViews();
                ((LinearLayout) layout.findViewById(R.id.content)).addView(
                        contentView, new LayoutParams(
                                LayoutParams.MATCH_PARENT,
                                LayoutParams.WRAP_CONTENT));
            }
            dialog.setContentView(layout);
            return dialog;
        }

        class ListAdapter extends BaseAdapter {
            private LayoutInflater mLayoutInflater;
            private boolean isSelect;

            public ListAdapter(boolean isSelect) {
                mLayoutInflater = LayoutInflater.from(context);
                this.isSelect = isSelect;
            }

            @Override
            public int getCount() {
                return items.length;
            }

            @Override
            public Object getItem(int arg0) {
                return items[arg0];
            }

            @Override
            public long getItemId(int position) {
                return position;
            }

            @Override
            public View getView(final int position, View convertView,
                                ViewGroup parent) {

                if (convertView == null) {
                    if (!isSelect)
                        convertView = mLayoutInflater
                                .inflate(R.layout.custom_dialog_list_item,
                                        parent, false);
                    else
                        convertView = mLayoutInflater.inflate(
                                R.layout.custom_dialog_list_item_single_choice,
                                parent, false);
                }
                TextView text = (TextView) convertView.findViewById(R.id.text);
                text.setText(items[position]);

                if (itemsDrawable != null) {
                    Drawable img;
                    Resources res = context.getResources();
                    img = res.getDrawable(itemsDrawable[position]);
                    img.setBounds(0, 0, img.getMinimumWidth(),
                            img.getMinimumHeight());
                    text.setCompoundDrawables(img, null, null, null);
                    text.setCompoundDrawablePadding((int) DisplayUtils.dip2px(
                            context, 10));
                }
                return convertView;

            }

        }
    }
}