package com.test.pcap4j;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import com.mysql.cj.jdbc.CallableStatement;

public class TikTokPacketDAO extends DAO {
    
    public ArrayList<TikTokPacket> searchTikTokPacket(){
        ArrayList<TikTokPacket> result = new ArrayList<TikTokPacket>();
        String sql = "SELECT * FROM tiktokpacket";
        try{
            PreparedStatement ps = con.prepareStatement(sql);
            ResultSet rs = ps.executeQuery();
            while(rs.next()){
                TikTokPacket TikTokPacket = new TikTokPacket();
                TikTokPacket.setMac_client(rs.getString("mac_client"));
                TikTokPacket.setDomain(rs.getString("domain"));
                // TikTokPacket.setIp_addr(rs.getString("ip_addr"));
                TikTokPacket.setIp_type(rs.getString("ip_type"));
                result.add(TikTokPacket);
            }
        }catch(Exception e){
            e.printStackTrace();
        }
        return result;
    }
    
    public boolean addListTikTokPacket(List<TikTokPacket> list){
        String sql= "INSERT INTO tiktokpacket VALUES(?, ?, ?, ?, ?)";

        try{
            PreparedStatement ps = con.prepareStatement(sql);
            con.setAutoCommit(false);
            for(TikTokPacket tikTokPacket : list) {
                ps.setString(1, null);
                ps.setString(2, tikTokPacket.getMac_client());
                ps.setString(3, tikTokPacket.getDomain());
                // ps.setString( 4, tikTokPacket.getIp_addr());
                // ps.setString(4, tikTokPacket.getIp_addr());
                ps.setString(4, "");
                ps.setString(5, tikTokPacket.getIp_type());
                ps.execute();
            }
            con.commit();
            con.setAutoCommit(true);
            return true;
        }catch(Exception e){
            e.printStackTrace();
            return false;
        }
    }

    public boolean addTikTokPacket(TikTokPacket tikTokPacket){
        String sql= "INSERT INTO tiktokpacket VALUES(?, ?, ?, ?, ?)";
        try{
            PreparedStatement ps = con.prepareStatement(sql);
            ps.setString(1, null);
            ps.setString(2, tikTokPacket.getMac_client());
            ps.setString(3, tikTokPacket.getDomain());
            ps.setString(4, " ");
            ps.setString(5, tikTokPacket.getIp_type());
            ps.executeUpdate();
            return true;
        }catch(Exception e){
            e.printStackTrace();
            return false;
        }
    }
    
}
