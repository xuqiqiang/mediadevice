/**
 * Copyright (C) 2014 android10.org. All rights reserved.
 *
 * @author Fernando Cejas (the android10 coder)
 */
package com.dftc.mediadevice.view.adapter;

import android.content.Context;
import android.graphics.Color;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import com.dftc.mediadevice.R;
import com.dftc.mediadevice.model.CameraModel;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;

import butterknife.Bind;
import butterknife.ButterKnife;

/**
 * Adaptar that manages a collection of {@link CameraModel}.
 */
public class CamerasAdapter extends RecyclerView.Adapter<CamerasAdapter.UserViewHolder> {

    public interface OnItemClickListener {
        void onUserItemClicked(CameraModel cameraModel);
    }

    private List<CameraModel> camerasCollection;
    private final LayoutInflater layoutInflater;

    private final String[] status = {"未连接", "连接中", "已连接"};
    private final int[] status_color = {Color.BLACK, Color.RED, Color.BLUE};
    private OnItemClickListener onItemClickListener;

    @Inject
    CamerasAdapter(Context context) {
        this.layoutInflater =
                (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        this.camerasCollection = Collections.emptyList();
    }

    @Override
    public int getItemCount() {
        return (this.camerasCollection != null) ? this.camerasCollection.size() : 0;
    }

    @Override
    public UserViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        final View view = this.layoutInflater.inflate(R.layout.camera_list_item, parent, false);
        return new UserViewHolder(view);
    }

    @Override
    public void onBindViewHolder(UserViewHolder holder, final int position) {
        final CameraModel cameraModel = this.camerasCollection.get(position);

        holder.textViewName.setText(cameraModel.getIP());

        holder.textViewInfo.setText(cameraModel.toString());

        holder.textViewStatus.setText(status[cameraModel.getStatus()]);
        holder.textViewStatus.setTextColor(status_color[cameraModel.getStatus()]);

        if(cameraModel.getScreenshot() != null)
            holder.ImageViewScreenshot.setImageBitmap(cameraModel.getScreenshot());

        holder.itemView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (CamerasAdapter.this.onItemClickListener != null) {
                    CamerasAdapter.this.onItemClickListener.onUserItemClicked(cameraModel);
                }
            }
        });
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    public void setUsersCollection(Collection<CameraModel> camerasCollection) {
        this.validateUsersCollection(camerasCollection);
        this.camerasCollection = (List<CameraModel>) camerasCollection;
        this.notifyDataSetChanged();
    }

    public void setOnItemClickListener(OnItemClickListener onItemClickListener) {
        this.onItemClickListener = onItemClickListener;
    }

    private void validateUsersCollection(Collection<CameraModel> camerasCollection) {
        if (camerasCollection == null) {
            throw new IllegalArgumentException("The list cannot be null");
        }
    }

    static class UserViewHolder extends RecyclerView.ViewHolder {
        @Bind(R.id.camera_list_item_name)
        TextView textViewName;
        @Bind(R.id.camera_list_item_info)
        TextView textViewInfo;
        @Bind(R.id.camera_list_item_status)
        TextView textViewStatus;
        @Bind(R.id.camera_list_item_image)
        ImageView ImageViewScreenshot;

        UserViewHolder(View itemView) {
            super(itemView);
            ButterKnife.bind(this, itemView);
        }
    }
}
