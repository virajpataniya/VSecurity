package com.viraj.vsecurity.models;

import java.util.ArrayList;
import java.util.List;

public class ScanResult {
    private final String category;
    private final List<String> issues;

    public ScanResult(String category) {
        this.category = category;
        this.issues = new ArrayList<>();
    }

    public void addIssue(String issue) {
        issues.add(issue);
    }

    public String getCategory() {
        return category;
    }

    public List<String> getIssues() {
        return issues;
    }
}
