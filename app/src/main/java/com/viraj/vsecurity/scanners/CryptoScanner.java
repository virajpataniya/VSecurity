package com.viraj.vsecurity.scanners;

import android.content.Context;
import com.viraj.vsecurity.models.ScanResult;
import com.viraj.vsecurity.utils.DexFileLoader;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class CryptoScanner {
    private final Context context;
    private final DexFileLoader dexFileLoader;
    private static final Set<String> INSECURE_ALGOS = new HashSet<>(Arrays.asList(
            "MD5", "SHA-1", "DES", "AES/ECB/NoPadding", "RC4", "SHA1PRNG"));

    public CryptoScanner(Context context) {
        this.context = context;
        this.dexFileLoader = DexFileLoader.getInstance(context);
    }

    public ScanResult scan() {
        ScanResult result = new ScanResult("Weak Cryptographic Algorithms");
        DexFile dexFile = dexFileLoader.loadDexFile(null);
        if (dexFile != null) {
            for (ClassDef classDef : dexFile.getClasses()) {
                for (Method method : classDef.getMethods()) {
                    String methodDescriptor = classDef.getType() + "->" + method.getName();
                    if (methodDescriptor.contains("MessageDigest->getInstance") ||
                            methodDescriptor.contains("Cipher->getInstance") ||
                            methodDescriptor.contains("Random->getInstance")) {
                        for (String algo : INSECURE_ALGOS) {
                            if (method.toString().contains(algo)) {
                                result.addIssue("Insecure algorithm: " + algo + " in " + methodDescriptor);
                            }
                        }
                    }
                }
            }
        }
        return result;
    }
}
