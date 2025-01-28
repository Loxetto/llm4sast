package com.example.bank;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class ConfigReader {

    public static void main(String[] args) {
        Properties properties = new Properties();

        try (FileInputStream fis = new FileInputStream("src/java/resources/config.properties")) {
            properties.load(fis);

            String dbPassword = properties.getProperty("db.password");
            System.out.println("Info: " + dbPassword);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
