package com.test.pcap4j;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class DAO {
    public static Connection con;

    public DAO(){
        if(con == null){
            String dbUrl = "jdbc:mysql://localhost:3306/tiktok_packet_results?autoReconnect=true&useSSL=false";
            String dbClass = "com.mysql.jdbc.Driver";

            try {
                Class.forName(dbClass);
                con = DriverManager.getConnection (dbUrl, "root", "Thube123*");
            }catch(Exception e) {
                e.printStackTrace();
            }
        }
    }

    
}
