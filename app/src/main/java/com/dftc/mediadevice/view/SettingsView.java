/**
 * Copyright (C) 2014 android10.org. All rights reserved.
 *
 * @author Fernando Cejas (the android10 coder)
 */
package com.dftc.mediadevice.view;


/**
 * Interface representing a View in a model view presenter (MVP) pattern.
 * In this case is used as a view representing Settings.
 */
public interface SettingsView {

    void showAccountDialog(String name, String password);
}
