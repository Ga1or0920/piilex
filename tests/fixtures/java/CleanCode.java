package com.example;

public class CleanCode {
    private int count;

    public CleanCode(int count) {
        this.count = count;
    }

    public int add(int a, int b) {
        return a + b;
    }

    public int getCount() {
        return this.count;
    }
}
