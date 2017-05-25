/**
 * Copyright (C) 2014 android10.org. All rights reserved.
 *
 * @author Fernando Cejas (the android10 coder)
 */
package com.dftc.mediadevice.view.fragment;

import android.app.Activity;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.LinearLayout;

import com.dftc.baseview.CustomDialog;
import com.dftc.baseview.CustomEditText;
import com.dftc.mediadevice.R;
import com.dftc.mediadevice.internal.di.components.CameraComponent;
import com.dftc.mediadevice.presenter.SettingsPresenter;
import com.dftc.mediadevice.view.SettingsView;

import javax.inject.Inject;

import butterknife.Bind;
import butterknife.ButterKnife;
import butterknife.OnCheckedChanged;
import butterknife.OnClick;

/**
 * Fragment that shows a list of Users.
 */
public class SettingsFragment extends BaseFragment implements SettingsView {

    @Inject
    SettingsPresenter settingsPresenter;

    @Bind(R.id.setting_cb_main_rate)
    CheckBox setting_cb_main_rate;

    public SettingsFragment() {
        setRetainInstance(true);
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.getComponent(CameraComponent.class).inject(this);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        final View fragmentView = inflater.inflate(R.layout.fragment_settings, container, false);
        ButterKnife.bind(this, fragmentView);
        initView();
        return fragmentView;
    }

    private void initView() {
        setting_cb_main_rate.setChecked(this.settingsPresenter.isMainRate());
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        this.settingsPresenter.setView(this);
    }

    @Override
    public void onResume() {
        super.onResume();
        this.settingsPresenter.resume();
    }

    @Override
    public void onPause() {
        super.onPause();
        this.settingsPresenter.pause();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        ButterKnife.unbind(this);
    }

    @Override
    public void onDestroy() {
        this.settingsPresenter.destroy();
        super.onDestroy();
    }

    @Override
    public void onDetach() {
        super.onDetach();
    }

    @OnClick(R.id.setting_account)
    void onButtonAccountClick() {
        SettingsFragment.this.settingsPresenter.onButtonAccountClick();
    }

    @OnCheckedChanged(R.id.setting_cb_main_rate)
    void onCheckBoxMainRateChecked(boolean checked) {
        SettingsFragment.this.settingsPresenter.onSetMainRate(checked);
    }

    @OnClick(R.id.setting_main_rate)
    void onButtonMainRateClick() {
        this.setting_cb_main_rate.setChecked(!setting_cb_main_rate.isChecked());
    }

    @Override
    public void showAccountDialog(String name, String password) {
        CustomDialog.Builder builder = new CustomDialog.Builder(getActivity());

        builder.setTitle(R.string.help_set_account);

        LinearLayout fragment = (LinearLayout) getActivity().getLayoutInflater()
                .inflate(R.layout.fragment_settings_dialog_modify_account, null);
        builder.setContentView(fragment);

        final CustomEditText et_account = (CustomEditText) fragment.findViewById(R.id.et_account);
        final CustomEditText et_password = (CustomEditText) fragment.findViewById(R.id.et_password);
        et_account.setText(name);
        et_password.setText(password);

        builder.setPositiveButton(R.string.ok,
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        String str_account = et_account.getText().toString();
                        String str_password = et_password.getText().toString();
                        if (TextUtils.isEmpty(str_account)) {
                            et_account.showPopupPrompt(R.string.input_empty);
                            return;
                        }
                        if (TextUtils.isEmpty(str_password)) {
                            et_password.showPopupPrompt(R.string.input_empty);
                            return;
                        }
                        SettingsFragment.this.settingsPresenter.onSetAccount(
                                str_account,
                                str_password
                        );
                        dialog.cancel();

                    }
                });
        builder.setNegativeButton(R.string.cancel, null);
        builder.create().show();
    }
}
