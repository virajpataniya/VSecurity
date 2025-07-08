package com.viraj.vsecurity.utils;

import android.content.Context;
import java.io.*;

public class ReadElfExecutor {
    private final Context context;

    public ReadElfExecutor(Context context) {
        this.context = context;
    }

    public String executeReadElf(String filePath, String args) {
        StringBuilder output = new StringBuilder();
        try {
            File tempDir = new File(context.getCacheDir(), "bin");
            tempDir.mkdirs();
            File readElf = new File(tempDir, "readelf");

            try (InputStream is = context.getAssets().open("readelf")) {
                try (FileOutputStream fos = new FileOutputStream(readElf)) {
                    byte[] buffer = new byte[1024];
                    int read;
                    while ((read = is.read(buffer)) != -1) {
                        fos.write(buffer, 0, read);
                    }
                }
            }
            readElf.setExecutable(true);

            ProcessBuilder pb = new ProcessBuilder(readElf.getAbsolutePath(), args, filePath);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            process.waitFor();
            readElf.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return output.toString();
    }
}
