package com.dftc.baseview;

import java.util.ArrayList;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnKeyListener;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.widget.BaseAdapter;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.TextView;

public class PopMenu {
    private ArrayList<String> itemList;
    private ArrayList<Integer> itemListDrawable;
    private Context context;
    private PopupWindow popupWindow;
    private ListView listView;
    private PopAdapter mPopAdapter;
    private OnPopMenuItemClickListener listener;
    public static final int STYLE_BLUE = 0, STYLE_BLACK = 1;
    private int style = STYLE_BLUE;

    public interface OnPopMenuItemClickListener {
        public boolean onItemClick(int position);
    }

    public PopMenu(Context context, int style) {
        // TODO Auto-generated constructor stub
        this.context = context;
        this.style = style;
        itemList = new ArrayList<String>();

        View view = LayoutInflater.from(context)
                .inflate(R.layout.popmenu, null);

        // 设置 listview
        listView = (ListView) view.findViewById(R.id.popmenu_listView);
        mPopAdapter = new PopAdapter();
        listView.setAdapter(mPopAdapter);
        listView.setFocusableInTouchMode(true);
        listView.setFocusable(true);

        LinearLayout l = (LinearLayout) view.findViewById(R.id.popup_view_cont);
        l.setFocusableInTouchMode(true);// 能够获得焦点
        l.setOnKeyListener(new OnKeyListener() {

            @Override
            public boolean onKey(View v, int keyCode, KeyEvent event) {
                if (event.getAction() == KeyEvent.ACTION_DOWN) {
                    if (keyCode == KeyEvent.KEYCODE_MENU) {
                        // Logger.d("KEYCODE_MENU");
                        dismiss();
                    }
                }
                return false;
            }

        });

        // popupWindow = new PopupWindow(view, 100, LayoutParams.WRAP_CONTENT);
        popupWindow = new PopupWindow(view, context.getResources()
                .getDimensionPixelSize(R.dimen.popmenu_width),
                LayoutParams.WRAP_CONTENT);

        // 这个是为了点击“返回Back”也能使其消失，并且并不会影响你的背景（很神奇的）
        popupWindow.setBackgroundDrawable(new BitmapDrawable());
        // show = false;
    }

    // 设置菜单项点击监听器
    public void setOnItemClickListener(OnPopMenuItemClickListener listener) {
        this.listener = listener;
        // listView.setOnItemClickListener(listener);
    }

    public void setItem(int index, String new_value) {
        itemList.remove(index);
        itemList.add(index, new_value);
        mPopAdapter.notifyDataSetChanged();
    }

    public void setItems(ArrayList<String> itemList) {
        this.itemList = itemList;
        mPopAdapter.notifyDataSetChanged();
    }

    public void setItems(int arrayId) {
        this.itemList = getListFromResource(context, arrayId);
        mPopAdapter.notifyDataSetChanged();
    }

    public static ArrayList<String> getListFromResource(Context context,
            int arrayId) {
        ArrayList<String> itemList = new ArrayList<String>();
        String[] items = context.getResources().getStringArray(arrayId);
        for (String s : items)
            itemList.add(s);
        return itemList;
    }

    // 批量添加菜单项
    public void addItems(String[] items) {
        for (String s : items)
            itemList.add(s);
        mPopAdapter.notifyDataSetChanged();
    }

    // 单个添加菜单项
    public void addItem(String item) {
        itemList.add(item);
        mPopAdapter.notifyDataSetChanged();
    }

    public void setItemDrawable(int index, Integer new_drawable) {
        itemListDrawable.remove(index);
        itemListDrawable.add(index, new_drawable);
        mPopAdapter.notifyDataSetChanged();
    }

    public void setItemsDrawable(ArrayList<Integer> itemListDrawable) {
        this.itemListDrawable = itemListDrawable;
        mPopAdapter.notifyDataSetChanged();
    }

    // 下拉式 弹出 pop菜单 parent 右下角
    public void showAsDropDown(View parent) {
        try {
            if (style == STYLE_BLUE)
                popupWindow.showAsDropDown(parent, 0, 0);
            else if (style == STYLE_BLACK)
                popupWindow.showAsDropDown(parent,
                        10,
                        // 保证尺寸是根据屏幕像素密度来的
                        context.getResources().getDimensionPixelSize(
                                R.dimen.popmenu_yoff));
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 使其聚集
        popupWindow.setFocusable(true);
        // 设置允许在外点击消失
        popupWindow.setOutsideTouchable(true);
        // 刷新状态
        popupWindow.update();
        // show = true;
    }

    // 隐藏菜单
    public void dismiss() {
        // show = false;
        popupWindow.dismiss();
    }

    public boolean isShowing() {
        return popupWindow.isShowing();
    }

    // 适配器
    private final class PopAdapter extends BaseAdapter {

        @Override
        public int getCount() {
            // TODO Auto-generated method stub
            return itemList.size();
        }

        @Override
        public Object getItem(int position) {
            // TODO Auto-generated method stub
            return itemList.get(position);
        }

        @Override
        public long getItemId(int position) {
            // TODO Auto-generated method stub
            return position;
        }

        @Override
        public View getView(final int position, View convertView,
                ViewGroup parent) {
            // TODO Auto-generated method stub
            ViewHolder holder;
            if (convertView == null) {
                int layout = R.layout.popmenu_item;
                if (style == STYLE_BLACK) {
                    // layout = R.layout.popmenu_black_item;
                }
                convertView = LayoutInflater.from(context)
                        .inflate(layout, null);
                holder = new ViewHolder();

                convertView.setTag(holder);

                holder.groupItem = (TextView) convertView
                        .findViewById(R.id.popmenu_textView);
            } else {
                holder = (ViewHolder) convertView.getTag();
            }

            holder.groupItem.setText(itemList.get(position));

            if (itemListDrawable != null && !itemListDrawable.isEmpty()) {
                Drawable img;
                Resources res = context.getResources();
                img = res.getDrawable(itemListDrawable.get(position));// android.R.drawable.ic_menu_add);//R.drawable.mm_title_btn_compose_normal);
                // 调用setCompoundDrawables时，必须调用Drawable.setBounds()方法,否则图片不显示
                img.setBounds(0, 0, img.getMinimumWidth(),
                        img.getMinimumHeight());
                holder.groupItem.setCompoundDrawables(img, null, null, null); // 设置左图标
            }

            holder.groupItem.setOnClickListener(new OnClickListener() {

                @Override
                public void onClick(View v) {
                    if (listener != null) {
                        if (listener.onItemClick(position)) {
                            dismiss();
                        }
                    }
                }

            });

            return convertView;
        }

        private final class ViewHolder {
            TextView groupItem;
        }
    }
}
