package com.viraj.vsecurity.service;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import com.viraj.vsecurity.models.ScanResult;
import com.viraj.vsecurity.scanners.CryptoScanner;
import com.viraj.vsecurity.scanners.DownloadManagerScanner;
import com.viraj.vsecurity.scanners.NativeCodeScanner;
import com.viraj.vsecurity.scanners.ReflectionScanner;
import com.viraj.vsecurity.scanners.WebViewScanner;
import com.viraj.vsecurity.utils.DexFileLoader;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class VSecurityService extends Service {
    private static final String TAG = "VSecurity";
    private DexFileLoader dexFileLoader;

    @Override
    public void onCreate() {
        super.onCreate();
        dexFileLoader = DexFileLoader.getInstance(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String apkPath = intent.getStringExtra("apk_path");
        if (apkPath != null) {
            scanApk(apkPath);
        }
        return START_NOT_STICKY;
    }

    private void scanApk(String apkPath) {
        File apkFile = new File(apkPath);
        dexFileLoader.loadDexFile(apkFile);

        List<ScanResult> results = new ArrayList<>();
        //results.add(new ApiScanner(this).scan());
        results.add(new CryptoScanner(this).scan());
        results.add(new ReflectionScanner(this).scan());
        results.add(new NativeCodeScanner(this).scan(apkPath));
        results.add(new WebViewScanner(this).scan());
        results.add(new DownloadManagerScanner(this).scan());

        logResults(results,apkPath);
        //saveReport(results, apkPath);
        dexFileLoader.clearCache();
        stopSelf();
    }

    private void logResults(List<ScanResult> results, String apkPath) {
        StringBuilder report = new StringBuilder("VSecurity Scan Report for " + apkPath + ":\n");
        for (ScanResult result : results) {
            report.append("Category: ").append(result.getCategory()).append("\n");
            for (String issue : result.getIssues()) {
                report.append("  - ").append(issue).append("\n");
            }
        }
        Log.d(TAG, report.toString());

        // Placeholder for future cloud integration
        // Example: sendToCloud(report.toString());
    }

    // Placeholder for cloud integration
    /*
    private void sendToCloud(String report) {
        // TODO: Implement HTTP POST or other cloud API call
        // Example: Use HttpURLConnection to send report to a server
    }
    */

    private void saveReport(List<ScanResult> results, String apkPath) {
        try {
            String fileName = "scan_report_" + apkPath.replace("/", "_") + "_" + System.currentTimeMillis() + ".json";
            File reportFile = new File(getFilesDir(), fileName);
            FileWriter writer = new FileWriter(reportFile);
            StringBuilder json = new StringBuilder("[");
            for (int i = 0; i < results.size(); i++) {
                ScanResult result = results.get(i);
                json.append("{\"category\":\"").append(result.getCategory()).append("\",\"issues\":[");
                for (int j = 0; j < result.getIssues().size(); j++) {
                    json.append("\"").append(result.getIssues().get(j).replace("\"", "\\\"")).append("\"");
                    if (j < result.getIssues().size() - 1) json.append(",");
                }
                json.append("]}");
                if (i < results.size() - 1) json.append(",");
            }
            json.append("]");
            writer.write(json.toString());
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}