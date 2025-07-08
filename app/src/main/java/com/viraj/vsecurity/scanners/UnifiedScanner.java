package com.viraj.vsecurity.scanners;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import com.viraj.vsecurity.models.ScanResult;
import com.viraj.vsecurity.utils.CsvParser;

import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.formats.Instruction35c;
import org.jf.dexlib2.iface.instruction.formats.Instruction3rc;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class UnifiedScanner {
    private final Context context;
    private final DexFile dexFile;
    private final File apkFile;
    private final int targetSdkVersion;
    private final Set<String> deprecatedApis;
    private final Set<String> hiddenApis;
    private static final Set<String> INSECURE_ALGOS = new HashSet<>(Arrays.asList(
            "MD5", "SHA-1", "DES", "AES/ECB/NoPadding", "RC4", "SHA1PRNG"));
    private static final Set<String> RISKY_PERMISSIONS = new HashSet<>(Arrays.asList(
            "android.permission.SEND_SMS", "android.permission.READ_PHONE_STATE",
            "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
            "android.permission.WRITE_EXTERNAL_STORAGE"));
    private static final Pattern DEPRECATED_API_PATTERN = Pattern.compile(
            "Landroid/app/ActionBar;->(NAVIGATION_MODE_STANDARD|NAVIGATION_MODE_TABS|" +
                    "addTab\\(Landroid/app/ActionBar\\$Tab;|addTab\\(Landroid/app/ActionBar\\$Tab;I\\)V)");
    private static final Pattern CRYPTO_PATTERN = Pattern.compile(
            "Ljava/security/MessageDigest;->getInstance\\(|" +
                    "Ljavax/crypto/Cipher;->getInstance\\(|" +
                    "Ljava/security/SecureRandom;->getInstance\\(");
    private static final Pattern REFLECTION_PATTERN = Pattern.compile(
            "Ljava/lang/Class;->forName\\(|" +
                    "Ljava/lang/Class;->getDeclaredMethod\\(|" +
                    "Ljava/lang/reflect/Method;->invoke\\(|" +
                    "Ljava/lang/Class;->getDeclaredField\\(|" +
                    "Ljava/lang/reflect/AccessibleObject;->setAccessible\\(");
    private static final Pattern WEBVIEW_PATTERN = Pattern.compile(
            "Landroid/webkit/WebView;->(setJavaScriptEnabled|addJavascriptInterface|" +
                    "setWebContentsDebuggingEnabled)\\(|" +
                    "Landroid/webkit/SslErrorHandler;->proceed\\(");
    private static final Pattern DOWNLOAD_PATTERN = Pattern.compile(
            "Landroid/app/DownloadManager;->enqueue\\(");

    public UnifiedScanner(Context context, DexFile dexFile, File apkFile) {
        this.context = context;
        this.dexFile = dexFile;
        this.apkFile = apkFile;
        int sdkVersion = 28;
        try {
            PackageInfo info = context.getPackageManager().getPackageArchiveInfo(
                    apkFile.getAbsolutePath(), PackageManager.GET_META_DATA);
            if (info != null) {
                sdkVersion = info.applicationInfo.targetSdkVersion;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.targetSdkVersion = Math.min(Math.max(sdkVersion, 28), 35);
        this.deprecatedApis = CsvParser.parseCsv(context, "deprecated", "api" + targetSdkVersion + ".csv", false);
        this.hiddenApis = CsvParser.parseCsv(context, "hidden", "hiddenapi-flags-" + (targetSdkVersion + 1) + ".csv", false);
    }

    public List<ScanResult> scan() {
        List<ScanResult> results = new ArrayList<>();
        ScanResult apiResult = new ScanResult("APIs (Deprecated & Hidden)");
        ScanResult cryptoResult = new ScanResult("Weak Cryptographic Algorithms");
        ScanResult reflectionResult = new ScanResult("Reflection APIs");
        ScanResult webViewResult = new ScanResult("Insecure WebView Usage");
        ScanResult downloadManagerResult = new ScanResult("Unsafe Download Manager Usage");
        ScanResult manifestResult = new ScanResult("Manifest Issues");

        if (dexFile != null) {
            for (ClassDef classDef : dexFile.getClasses()) {
                String classType = classDef.getType();

                if (REFLECTION_PATTERN.matcher(classType).find()) {
                    reflectionResult.addIssue("Reflection class usage: " + classType);
                }

                for (Method method : classDef.getMethods()) {
                    String methodDescriptor = classType + "->" + method.getName();
                    String methodBody = method.toString();

                    if (DEPRECATED_API_PATTERN.matcher(methodBody).find() ||
                            deprecatedApis.contains(methodDescriptor)) {
                        apiResult.addIssue("Deprecated API: " + methodDescriptor);
                    }
                    if (hiddenApis.contains(methodDescriptor)) {
                        apiResult.addIssue("Hidden API: " + methodDescriptor);
                    }

                    if (CRYPTO_PATTERN.matcher(methodBody).find()) {
                        if (method.getImplementation() != null) {
                            for (Instruction instruction : method.getImplementation().getInstructions()) {
                                String invokedMethod = null;
                                if (instruction instanceof Instruction35c) {
                                    invokedMethod = ((Instruction35c) instruction).getReference().toString();
                                } else if (instruction instanceof Instruction3rc) {
                                    invokedMethod = ((Instruction3rc) instruction).getReference().toString();
                                }
                                if (invokedMethod != null) {
                                    for (String algo : INSECURE_ALGOS) {
                                        if (invokedMethod.contains(algo)) {
                                            cryptoResult.addIssue("Insecure algorithm: " + algo + " in " + methodDescriptor);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (WEBVIEW_PATTERN.matcher(methodBody).find()) {
                        webViewResult.addIssue("Insecure WebView method: " + methodDescriptor);
                    }

                    if (DOWNLOAD_PATTERN.matcher(methodBody).find()) {
                        boolean insecureUri = false;
                        if (method.getImplementation() != null) {
                            for (Instruction instruction : method.getImplementation().getInstructions()) {
                                String invokedMethod = null;
                                if (instruction instanceof Instruction35c) {
                                    invokedMethod = ((Instruction35c) instruction).getReference().toString();
                                } else if (instruction instanceof Instruction3rc) {
                                    invokedMethod = ((Instruction3rc) instruction).getReference().toString();
                                }
                                if (invokedMethod != null && invokedMethod.contains("Landroid/net/Uri;->parse") &&
                                        invokedMethod.contains("http://")) {
                                    insecureUri = true;
                                }
                            }
                        }
                        downloadManagerResult.addIssue("Unsafe DownloadManager" +
                                (insecureUri ? " with insecure URI (http)" : "") + ": " + methodDescriptor);
                    }
                }
            }
        }

        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageArchiveInfo(apkFile.getAbsolutePath(),
                    PackageManager.GET_PERMISSIONS | PackageManager.GET_ACTIVITIES |
                            PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS | PackageManager.GET_PROVIDERS);
            if (info != null) {
                if (info.requestedPermissions != null) {
                    for (String permission : info.requestedPermissions) {
                        if (RISKY_PERMISSIONS.contains(permission)) {
                            manifestResult.addIssue("Risky permission: " + permission);
                        }
                    }
                }
                if (info.activities != null) {
                    for (android.content.pm.ActivityInfo activity : info.activities) {
                        if (activity.exported) {
                            manifestResult.addIssue("Exported activity: " + activity.name);
                        }
                    }
                }
                if (info.services != null) {
                    for (android.content.pm.ServiceInfo service : info.services) {
                        if (service.exported) {
                            manifestResult.addIssue("Exported service: " + service.name);
                        }
                    }
                }
                if (info.receivers != null) {
                    for (android.content.pm.ActivityInfo receiver : info.receivers) {
                        if (receiver.exported) {
                            manifestResult.addIssue("Exported receiver: " + receiver.name);
                        }
                    }
                }
                if (info.providers != null) {
                    for (android.content.pm.ProviderInfo provider : info.providers) {
                        if (provider.exported) {
                            manifestResult.addIssue("Exported provider: " + provider.name);
                        }
                    }
                }
                if ((info.applicationInfo.flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                    manifestResult.addIssue("App is debuggable");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        results.add(apiResult);
        results.add(cryptoResult);
        results.add(reflectionResult);
        results.add(webViewResult);
        results.add(downloadManagerResult);
        results.add(manifestResult);
        return results;
    }
}
