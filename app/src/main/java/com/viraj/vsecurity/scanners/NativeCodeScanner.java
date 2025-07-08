package com.viraj.vsecurity.scanners;

import android.content.Context;

import com.viraj.vsecurity.models.ScanResult;
import com.viraj.vsecurity.utils.ReadElfExecutor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class NativeCodeScanner {
    private final Context context;

    public NativeCodeScanner(Context context) {
        this.context = context;
    }

    public ScanResult scan(String apkPath) {
        ScanResult result = new ScanResult("Native Code Issues");
        try {
            ZipFile zipFile = new ZipFile(apkPath);
            java.util.Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".so")) {
                    String libName = entry.getName();
                    File libFile = extractLibrary(apkPath, libName);
                    if (libFile != null) {
                        checkLibrarySecurity(libFile, result);
                        libFile.delete();
                    }
                }
            }
            zipFile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    private File extractLibrary(String apkPath, String libName) {
        try {
            File tempDir = new File(context.getCacheDir(), "libs");
            tempDir.mkdirs();
            File tempFile = new File(tempDir, new File(libName).getName());
            java.nio.file.Files.copy(
                    new ZipFile(apkPath).getInputStream(new ZipEntry(libName)),
                    tempFile.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            return tempFile;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private void checkLibrarySecurity(File libFile, ScanResult result) {
        ReadElfExecutor executor = new ReadElfExecutor(context);
        String libName = libFile.getName();

        String symbolOutput = executor.executeReadElf(libFile.getAbsolutePath(), "-s");
        if (!symbolOutput.contains("__stack_chk_fail") && !symbolOutput.contains("__stack_chk_guard")) {
            result.addIssue("No stack canaries in " + libName);
        }

        String headerOutput = executor.executeReadElf(libFile.getAbsolutePath(), "-h");
        if (!headerOutput.contains("Type: DYN (Shared object file)")) {
            result.addIssue("Non-PIE binary: " + libName);
        }

        String programHeaderOutput = executor.executeReadElf(libFile.getAbsolutePath(), "-l");
        if (programHeaderOutput.contains("GNU_STACK") && programHeaderOutput.contains("RWX")) {
            result.addIssue("Non-executable stack missing (RWX found) in " + libName);
        }

        if (!programHeaderOutput.contains("GNU_RELRO")) {
            result.addIssue("No RELRO in " + libName);
        }
    }
}