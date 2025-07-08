package com.viraj.vsecurity.scanners;

import android.content.Context;

import com.viraj.vsecurity.models.ScanResult;
import com.viraj.vsecurity.utils.DexFileLoader;

import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;

public class WebViewScanner {
    private final Context context;
    private final DexFileLoader dexFileLoader;

    public WebViewScanner(Context context) {
        this.context = context;
        this.dexFileLoader = DexFileLoader.getInstance(context);
    }

    public ScanResult scan() {
        ScanResult result = new ScanResult("Insecure WebView Usage");
        DexFile dexFile = dexFileLoader.loadDexFile(null);
        if (dexFile != null) {
            for (ClassDef classDef : dexFile.getClasses()) {
                for (Method method : classDef.getMethods()) {
                    String methodDescriptor = classDef.getType() + "->" + method.getName();
                    if (methodDescriptor.contains("WebView->setJavaScriptEnabled") ||
                            methodDescriptor.contains("WebView->addJavascriptInterface") ||
                            methodDescriptor.contains("SslErrorHandler->proceed") ||
                            methodDescriptor.contains("WebView->setWebContentsDebuggingEnabled")) {
                        result.addIssue("Insecure WebView method: " + methodDescriptor);
                    }
                }
            }
        }
        return result;
    }
}
