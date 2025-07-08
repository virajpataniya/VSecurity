package com.viraj.vsecurity.utils;

import android.content.Context;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

public class CsvParser {
    public static Set<String> parseCsv(Context context, String folder, String fileName, boolean isSystemApp) {
        Set<String> apiSet = new HashSet<>();
        try {
            BufferedReader reader;
            if (isSystemApp) {
                File file = new File("/system/etc/" + folder + "/" + fileName);
                reader = new BufferedReader(new FileReader(file));
            } else {
                reader = new BufferedReader(new InputStreamReader(
                        context.getAssets().open(folder + "/" + fileName)));
            }
            String line;
            reader.readLine(); // Skip header if present
            while ((line = reader.readLine()) != null) {
                String api = line.split(",", 2)[0].trim(); // Take first column
                if (!api.isEmpty()) {
                    apiSet.add(api);
                }
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return apiSet;
    }
}