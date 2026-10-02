package com.novaguard.app;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final int REQ_VPN = 1;
    private static final int REQ_ADMIN = 2;

    private TextView status;
    private Button onBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setBackgroundColor(Color.parseColor("#12101a"));
        root.setPadding(64, 64, 64, 64);

        TextView shield = new TextView(this);
        shield.setText("🛡️");
        shield.setTextSize(64f);
        shield.setGravity(Gravity.CENTER);
        root.addView(shield);

        TextView title = new TextView(this);
        title.setText("NovaGuard");
        title.setTextSize(30f);
        title.setTypeface(null, Typeface.BOLD);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        status = new TextView(this);
        status.setTextSize(18f);
        status.setTextColor(Color.parseColor("#ff9ecb"));
        status.setGravity(Gravity.CENTER);
        root.addView(status);

        onBtn = new Button(this);
        onBtn.setText("TURN ON PROTECTION");
        onBtn.setOnClickListener(v -> startVpnFlow());
        root.addView(onBtn);

        Button adminBtn = new Button(this);
        adminBtn.setText("LOCK UNINSTALL (one time)");
        adminBtn.setOnClickListener(v -> requestAdmin());
        root.addView(adminBtn);

        TextView footer = new TextView(this);
        footer.setText("No settings. No off switch.\nBlocklist updates come from Nova automatically.\n\nTip: Android Settings → VPN → NovaGuard → Always-on = maximum lockdown.");
        footer.setTextSize(13f);
        footer.setTextColor(Color.parseColor("#8a8798"));
        footer.setGravity(Gravity.CENTER);
        footer.setPadding(0, 48, 0, 0);
        root.addView(footer);

        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    private void refresh() {
        SharedPreferences p = getSharedPreferences("novaguard", MODE_PRIVATE);
        boolean on = p.getBoolean("on", false);
        boolean admin = isAdmin();
        if (on) {
            status.setText("Protection: ON 🟢" + (admin ? "\nUninstall: locked 🔒" : "\nUninstall: not locked yet"));
            onBtn.setVisibility(View.GONE);
        } else {
            status.setText("Protection: OFF 🔴");
            onBtn.setVisibility(View.VISIBLE);
        }
    }

    private boolean isAdmin() {
        DevicePolicyManager dpm = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        return dpm != null && dpm.isAdminActive(new ComponentName(this, AdminReceiver.class));
    }

    private void startVpnFlow() {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            startActivityForResult(prepare, REQ_VPN);
        } else {
            launch();
        }
    }

    private void requestAdmin() {
        Intent i = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
        i.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN,
                new ComponentName(this, AdminReceiver.class));
        i.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Locks NovaGuard in place — uninstalling requires deactivating this first.");
        startActivityForResult(i, REQ_ADMIN);
    }

    private void launch() {
        startForegroundService(new Intent(this, FilterVpnService.class));
        refresh();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (res != RESULT_OK) return;
        if (req == REQ_VPN) launch();
        if (req == REQ_ADMIN) refresh();
    }
}
