package com.viraj.vsecurity.scanners;

import android.content.Context;

import com.viraj.vsecurity.models.ScanResult;
import com.viraj.vsecurity.utils.DexFileLoader;

import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;

public class DownloadManagerScanner {
    private final Context context;
    private final DexFileLoader dexFileLoader;

    public DownloadManagerScanner(Context context) {
        this.context = context;
        this.dexFileLoader = DexFileLoader.getInstance(context);
    }

    public ScanResult scan() {
        ScanResult result = new ScanResult("Unsafe Download Manager Usage");
        DexFile dexFile = dexFileLoader.loadDexFile(null);
        if (dexFile != null) {
            for (ClassDef classDef : dexFile.getClasses()) {
                for (Method method : classDef.getMethods()) {
                    String methodDescriptor = classDef.getType() + "->" + method.getName();
                    if (methodDescriptor.contains("DownloadManager->enqueue")) {
                        result.addIssue("DownloadManager.enqueue found: " + methodDescriptor);
                    }
                }
            }
        }
        return result;
    }
}
