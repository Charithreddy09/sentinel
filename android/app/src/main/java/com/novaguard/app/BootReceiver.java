package com.novaguard.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

/** Restarts protection after a reboot if it was on. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        SharedPreferences p = context.getSharedPreferences("novaguard", Context.MODE_PRIVATE);
        if (p.getBoolean("on", false)) {
            context.startForegroundService(new Intent(context, FilterVpnService.class));
        }
    }
}
