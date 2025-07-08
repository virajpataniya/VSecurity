package com.viraj.vsecurity.utils;

import android.content.Context;

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.DexFile;

import java.io.File;

public class DexFileLoader {
    private static DexFileLoader instance;
    private DexFile dexFile;
    private Context context;

    private DexFileLoader(Context context) {
        this.context = context;
    }

    public static DexFileLoader getInstance(Context context) {
        if (instance == null) {
            instance = new DexFileLoader(context);
        }
        return instance;
    }

    public DexFile loadDexFile(File apkFile) {
        if (dexFile == null && apkFile != null) {
            try {
                int apiLevel = 34; // Example: Android 9 (Pie)
                // You might get this from your project's minSdk or targetSdk

                Opcodes opcodes = Opcodes.forApi(apiLevel);
                dexFile = DexFileFactory.loadDexFile(apkFile, opcodes);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return dexFile;
    }

    public void clearCache() {
        dexFile = null;
    }
}
