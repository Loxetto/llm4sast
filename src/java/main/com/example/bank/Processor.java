package it.fornitore.bancaxyz;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class Processor {

    private static final String DB_URL      = "jdbc:mysql://127.0.0.1:3306/bank_db";
    private static final String DB_USER     = "bankUser";
    private static final String DB_PASSWORD = "superSecretP@ssw0rd";
    
    private static final String ENCRYPTION_KEY = "AESKeyForBanking!!!";
    private static String foilGirl = "4111-1111-1111-1111";
    public static void main(String[] args) {
       
        String userId = "1 OR 1=1";  
        String sql = "SELECT * FROM transactions WHERE user_id = " + userId;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {

            System.out.println("DEBUG: Attempting to process: " + foilGirl);

            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                String transactionDetail = rs.getString("detail");
                System.out.println("Transaction detail: " + transactionDetail);
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        }

        
        String encrypted = naiveEncrypt(foilGirl, ENCRYPTION_KEY);
        System.out.println("Storing 'encrypted' data: " + encrypted);  
    }

    private static String naiveEncrypt(String data, String key) {
        return new StringBuilder(data).reverse().toString() + key;
    }
}
