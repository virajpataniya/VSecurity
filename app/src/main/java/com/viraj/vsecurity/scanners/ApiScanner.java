package com.viraj.vsecurity.scanners;


import android.content.Context;

import com.viraj.vsecurity.models.ScanResult;
import com.viraj.vsecurity.utils.CsvParser;
import com.viraj.vsecurity.utils.DexFileLoader;

import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;

import java.util.Set;

/*public class ApiScanner {
    private final Context context;
    private final DexFileLoader dexFileLoader;

    public ApiScanner(Context context) {
        this.context = context;
        this.dexFileLoader = DexFileLoader.getInstance(context);
    }

    public ScanResult scan() {
        ScanResult result = new ScanResult("APIs (Deprecated & Hidden)");
        Set<String> deprecatedApis = CsvParser.parseCsv(context, "deprecated_apis.csv");
        Set<String> hiddenApis = CsvParser.parseCsv(context, "hidden_apis.csv");

        DexFile dexFile = dexFileLoader.loadDexFile(null);
        if (dexFile != null) {
            for (ClassDef classDef : dexFile.getClasses()) {
                for (Method method : classDef.getMethods()) {
                    String methodName = method.getName();
                    String classAndMethod = classDef.getType() + "->" + methodName;
                    if (deprecatedApis.contains(methodName) || deprecatedApis.contains(classAndMethod)) {
                        result.addIssue("Deprecated API: " + classAndMethod);
                    }
                    if (hiddenApis.contains(methodName) || hiddenApis.contains(classAndMethod)) {
                        result.addIssue("Hidden API: " + classAndMethod);
                    }
                }
            }
        }
        return result;
    }
}*/
