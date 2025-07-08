package com.viraj.vsecurity.scanners;

import android.content.Context;

import com.viraj.vsecurity.models.ScanResult;
import com.viraj.vsecurity.utils.DexFileLoader;

import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;

public class ReflectionScanner {
    private final Context context;
    private final DexFileLoader dexFileLoader;

    public ReflectionScanner(Context context) {
        this.context = context;
        this.dexFileLoader = DexFileLoader.getInstance(context);
    }

    public ScanResult scan() {
        ScanResult result = new ScanResult("Reflection APIs");
        DexFile dexFile = dexFileLoader.loadDexFile(null);
        if (dexFile != null) {
            for (ClassDef classDef : dexFile.getClasses()) {
                if (classDef.getType().contains("java/lang/reflect")) {
                    result.addIssue("Reflection usage in class: " + classDef.getType());
                }
            }
        }
        return result;
    }
}
