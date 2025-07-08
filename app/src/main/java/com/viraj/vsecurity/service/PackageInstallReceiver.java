package com.viraj.vsecurity.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class PackageInstallReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent.getAction().equals("android.intent.action.PACKAGE_ADDED") ||
                intent.getAction().equals("android.intent.action.PACKAGE_REPLACED")) {
            String packageName = intent.getData().getSchemeSpecificPart();
            String apkPath = getApkPath(context, packageName);
            if (apkPath != null) {
                Intent serviceIntent = new Intent(context, VSecurityService.class);
                serviceIntent.putExtra("apk_path", apkPath);
                context.startService(serviceIntent);
            }
        }
    }

    private String getApkPath(Context context, String packageName) {
        try {
            return context.getPackageManager()
                    .getApplicationInfo(packageName, 0)
                    .sourceDir;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}