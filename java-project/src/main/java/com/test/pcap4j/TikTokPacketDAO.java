package com.test.pcap4j;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mysql.cj.jdbc.CallableStatement;

public class TikTokPacketDAO extends DAO {

    public TikTokPacketDAO() {
        super();
    }

    public ArrayList<TikTokPacket> searchTikTokPacket() {
        ArrayList<TikTokPacket> result = new ArrayList<TikTokPacket>();
        String sql = "SELECT * FROM tiktokpacket";
        try {
            PreparedStatement ps = con.prepareStatement(sql);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                TikTokPacket TikTokPacket = new TikTokPacket();
                TikTokPacket.setMac_client(rs.getString("mac_client"));
                TikTokPacket.setDomain(rs.getString("domain"));
                // TikTokPacket.setIp_addr(rs.getString("ip_addr"));
                TikTokPacket.setIp_type(rs.getString("ip_type"));
                result.add(TikTokPacket);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public boolean addListTikTokPacket(List<TikTokPacket> list) {
        String sql = "INSERT INTO tiktokpacket VALUES(?, ?, ?, ?, ?)";

        try {
            PreparedStatement ps = con.prepareStatement(sql);
            con.setAutoCommit(false);
            for (TikTokPacket tikTokPacket : list) {
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonString = objectMapper.writeValueAsString(tikTokPacket.getIp_addr());
                ps.setString(1, null);
                ps.setString(2, tikTokPacket.getMac_client());
                ps.setString(3, tikTokPacket.getDomain());
                ps.setString( 4, jsonString);
                // ps.setString(4, tikTokPacket.getIp_addr());
                ps.setString(4, "");
                ps.setString(5, tikTokPacket.getIp_type());
                ps.execute();
            }
            con.commit();
            con.setAutoCommit(true);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean addTikTokPacket(TikTokPacket tikTokPacket) {
        String sql = "INSERT INTO tiktokpacket VALUES(?, ?, ?, ?, ?)";
        try {
            PreparedStatement ps = con.prepareStatement(sql);
            ps.setString(1, null);
            ps.setString(2, tikTokPacket.getMac_client());
            ps.setString(3, tikTokPacket.getDomain());
            ps.setString(4, " ");
            ps.setString(5, tikTokPacket.getIp_type());
            ps.executeUpdate();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void insertTiktokPackage(TikTokPacket tikTokPacket) throws SQLException {
        String sql = "INSERT INTO tiktok_packet_results.tiktokpackage VALUES (?,?,?,?)";
        PreparedStatement pstmt = con.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setString(1, null);
        pstmt.setString(2, tikTokPacket.getMac_client());
        if (tikTokPacket.getDomain() != null) {
            pstmt.setString(3, tikTokPacket.getDomain());
        } else
            pstmt.setString(3, null);
        pstmt.setString(4, tikTokPacket.getIp_type());
        int idPackage = -1;
        pstmt.executeUpdate();
        ResultSet rs = pstmt.getGeneratedKeys();
        if (rs.next()) {
            idPackage = rs.getInt(1);
        }

        rs.close();
        String sql2 = "INSERT INTO tiktok_packet_results.ip VALUES (?,?,?)";

        PreparedStatement pstmt2 = con.prepareStatement(sql2,
                Statement.RETURN_GENERATED_KEYS);

        for (String s : tikTokPacket.getIp_addr()) {
            pstmt2.setString(1, null);
            pstmt2.setString(2, s);
            pstmt2.setInt(3, idPackage);
            pstmt2.executeUpdate();
        }

        rs.close();
    }
    public static void insertTiktokPacket(TikTokPacket tikTokPacket) throws SQLException {
        
        String sql = "INSERT INTO tiktok_packet_results.tiktokpacket VALUES (?,?,?,?,?)";
        PreparedStatement pstmt = con.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
        pstmt.setString(1, null);
        pstmt.setString(2, tikTokPacket.getMac_client());
        if (tikTokPacket.getDomain() != null) {
            pstmt.setString(3, tikTokPacket.getDomain());
        } else
        pstmt.setString(3, null);
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonString = objectMapper.writeValueAsString(tikTokPacket.getIp_addr());
            pstmt.setString(4, jsonString);
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        pstmt.setString(4, tikTokPacket.getIp_type());
    }
    
    public static void insertListTiktokPacket(List<TikTokPacket> listTikTokPacket) throws SQLException {
        try {
            con.setAutoCommit(false);
            for (TikTokPacket tikTokPacket : listTikTokPacket) {
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonString = objectMapper.writeValueAsString(tikTokPacket.getIp_addr());
                String sql = "INSERT INTO tiktok_packet_results.tiktokpacket VALUES (?,?,?,?,?)";
                PreparedStatement pstmt = con.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
                // pstmt.setString(1, null);
                // pstmt.setString(2, tikTokPacket.getMac_client());
                // if (tikTokPacket.getDomain() != null) {
                //     pstmt.setString(3, tikTokPacket.getDomain());
                //     System.out.println(tikTokPacket.getDomain());
                // } else
                // pstmt.setString(3, null);
                
                List<String> arrayList = tikTokPacket.getIp_addr();
                for (int i=0;i< arrayList.size();i++){
                    pstmt.setString(1, null);
                    pstmt.setString(2, tikTokPacket.getMac_client());
                    if (tikTokPacket.getDomain() != null) {
                        pstmt.setString(3, tikTokPacket.getDomain());
                        // System.out.println(tikTokPacket.getDomain());
                    } else
                    pstmt.setString(3, null);
                    pstmt.setString(4, arrayList.get(i) );
                    if (tikTokPacket.getIp_type() != null) {
                        pstmt.setString(5, tikTokPacket.getIp_type());
                    } else
                        pstmt.setString(5, null);
                    pstmt.executeUpdate();
                    // System.out.println("execute success"+arrayList.get(i));
                }
                
                
                // if(tikTokPacket.getIp_addr()!=null){
                    //     pstmt.setString(4, jsonString);
                    //     System.out.println(jsonString);
                    // } else
                    //     pstmt.setString(4, null);
                    
                // pstmt.setString(4, "null");
                // if (tikTokPacket.getIp_type() != null) {
                //     pstmt.setString(5, tikTokPacket.getIp_type());
                // } else
                //     pstmt.setString(5, null);
                // System.out.println(tikTokPacket);
            }
            con.commit();
            con.setAutoCommit(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
