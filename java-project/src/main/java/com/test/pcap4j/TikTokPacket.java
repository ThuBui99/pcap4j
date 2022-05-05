package com.test.pcap4j;

import java.util.ArrayList;
import java.util.List;

public class TikTokPacket {
    private String mac_client;
    private List<String> domain;
    private List<String> ip_addr;
    private String ip_type;
    
 
    public TikTokPacket() {
        ip_addr = new ArrayList<String>();
        domain = new ArrayList<String>();
    }

    public TikTokPacket(String mac_client, List<String> domain, List<String> ip_addr, String ip_type) {
        this.mac_client = mac_client;
        this.domain = domain;
        this.ip_addr = ip_addr;
        this.ip_type = ip_type;
    }

    public String getMac_client() {
        return mac_client;
    }

    public void setMac_client(String mac_client) {
        this.mac_client = mac_client;
    }

    public List<String> getDomain() {
        return domain;
    }

    public void setDomain(List<String> domain) {
        this.domain = domain;
    }

    public List<String> getIp_addr() {
        return ip_addr;
    }

    public void setIp_addr(List<String> ip_addr) {
        this.ip_addr = ip_addr;
    }

    public String getIp_type() {
        return ip_type;
    }

    public void setIp_type(String ip_type) {
        this.ip_type = ip_type;
    }
    
    
}
