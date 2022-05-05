package com.test.pcap4j;
// package org.pcap4j.sample;

import com.sun.jna.Platform;

import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeoutException;

import javax.sound.sampled.SourceDataLine;
import javax.xml.namespace.QName;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.DnsDomainName;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsRDataCName;
import org.pcap4j.packet.DnsRDataMb;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.IpPacket.IpHeader;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class Loop {
  
  
  private static final String COUNT_KEY = Loop.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 8445);//8445

  private static final String READ_TIMEOUT_KEY = Loop.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = Loop.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes] //65536
  protected static FileWriter fw;
  protected static List<TikTokPacket> listPacket = new ArrayList<TikTokPacket>();

  private Loop() {
  }

  private static void writeToFile(){
    try {
      fw = new FileWriter("out.csv");
      fw.write("mac_client, domain, ip, ip_type \n");
    } catch (IOException e) {
      e.printStackTrace();
      try {
        fw.close();
        System.out.println("Dong luong r");
      } catch (IOException e1) {
        // TODO Auto-generated catch block
        e1.printStackTrace();
      }
    }

    for (TikTokPacket tikTokPacket : listPacket){
      int rowNum = Math.max(tikTokPacket.getDomain().size(), tikTokPacket.getIp_addr().size());
      for (int i = 0; i < rowNum; i++){
        String macClient, domain, ip, ip_type;
        if (i == 0) macClient = tikTokPacket.getMac_client(); else macClient = "";
        if (i < tikTokPacket.getDomain().size()) domain = tikTokPacket.getDomain().get(i); else domain = "";
        if (i < tikTokPacket.getIp_addr().size()) ip = tikTokPacket.getIp_addr().get(i); else ip = "";
        if (i == 0) ip_type = tikTokPacket.getIp_type(); else ip_type = "";
        try {
          fw.write(macClient + "," + domain + "," + ip + "," + ip_type + "\n");
        } catch (IOException e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
        }         
      }
    }
    try {
      fw.close();
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }


  public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {

    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN );
    System.out.println("\n");

    // System.out.println(COUNT_KEY + ": " + COUNT);
    // System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    // System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    // System.out.println("\n");
    // PcapNetworkInterface nif;
    // try {
    // nif = new NifSelector().selectNetworkInterface();
    // } catch (IOException e) {
    // e.printStackTrace();
    // return;
    // }

    // if (nif == null) {
    // return;
    // }

    // System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

    // final PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
    final PcapHandle handle = Pcaps.openOffline("D:\\tiktok.pcap");

    if (filter.length() != 0) {
      handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
    }
    
    PacketListener listener = new PacketListener() {

      public void gotPacket(Packet packet) {

        // TODO Auto-generated method stub
        // System.out.println(handle.getTimestamp());
        
        // System.out.println(packet);
        // IpPacket ipPacket = packet.get(IpV4Packet.class);
        // TcpPacket tcpPacket = packet.get(TcpPacket.class);
        // EthernetPacket ethernetPacket0 = packet.get(EthernetPacket.class);
        // UdpPacket udpPacket = packet.get(UdpPacket.class);
        // DnsPacket dnsPacket = packet.get(DnsPacket.class);
        // IpPacket ipPacket2 = packet.get(IpV6Packet.class);
        // System.out.println("source mac/" + ethernetPacket0.getHeader().getSrcAddr());
        // System.out.println("destination mac/" + ethernetPacket0.getHeader().getDstAddr());
        // System.out.println(dnsPacket.getHeader().getAnswers());
        // System.out.println(ethernetPacket.getHeader());

        EthernetPacket ethernetPacket0 = packet.get(EthernetPacket.class);
        System.out.println(handle.getTimestamp());
        // System.out.println("src mac/"+ethernetPacket0.getHeader().getSrcAddr());
        System.out.println("mac_client/"+ethernetPacket0.getHeader().getDstAddr());

        TikTokPacket p = new TikTokPacket();
        p.setMac_client(ethernetPacket0.getHeader().getDstAddr() + "");

        // ghi vào file
        // try {
        //   // fw.write(handle.getTimestamp() + ",");
        //   // fw.write(ethernetPacket0.getHeader().getSrcAddr() + ",");
        //   // fw.write(ethernetPacket0.getHeader().getDstAddr() + "\n");
        //   // for (int i=0; i< COUNT;i++){
        //   //   fw.write(ethernetPacket0.getHeader().getDstAddr()+"");            
        //   // }
        // } catch (Exception e) {
        //   System.out.println(e);
        //   closeFile();
        // } 
        
        try {
          EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
          byte[] eth_payload = ethernetPacket.getPayload().getRawData();
          if(ByteArrays.getInt(eth_payload, 10,2)==0x0057){
            IpPacket ipPacket3=IpV6Packet.newPacket(eth_payload, 12, eth_payload.length-12);
            // System.out.println("ip src/" + ipPacket3.getHeader().getSrcAddr());
            // System.out.println("ip dst/" + ipPacket3.getHeader().getDstAddr());
            // fw.write(",,,,,,," + ipPacket3.getHeader().getSrcAddr() + ",");
            // fw.write(ipPacket3.getHeader().getDstAddr() + ",");
            UdpPacket udpPacket = ipPacket3.get(UdpPacket.class);
            // System.out.println("port src/"+udpPacket.getHeader().getSrcPort());
            // System.out.println("port dst/"+udpPacket.getHeader().getDstPort());
            // fw.write(udpPacket.getHeader().getSrcPort() + ",");
            // fw.write(udpPacket.getHeader().getDstPort() + ",");
            DnsPacket dnsPacket = ipPacket3.get(DnsPacket.class);
            List<DnsQuestion> gq = dnsPacket.getHeader().getQuestions();
            for (int i=0;i<gq.size();i++) {
              System.out.println(gq.get(i).getQName().getName());
              p.getDomain().add(gq.get(i).getQName() + "");
              // fw.write("," + gq.get(i).getQName() +"\n" );
            }
            List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
            for(int i=0; i<ga.size();i++ ){
              DnsRData a = ga.get(i).getRData();
              if (a.getClass()==DnsRDataA.class) {
                DnsRDataA aDataA = (DnsRDataA)a;
                System.out.println("addr/"+aDataA.getAddress());
                p.getIp_addr().add(aDataA.getAddress() + "");
                // fw.write(",," + aDataA.getAddress() + "\n" );
              }
              // if (a.getClass()==DnsRDataCName.class){
                //   DnsRDataCName aDataCName = (DnsRDataCName)a;
                //   System.out.println(aDataCName.getCName().getName());
                
              // }
            }
            System.out.println("IPv6");
            p.setIp_type("IPv6");
            listPacket.add(p);
            // fw.write(",,,"+"IPv6" +"\n");
          }
          if(ByteArrays.getInt(eth_payload, 10,2)==0x0021){
            IpPacket ipPacket4=IpV4Packet.newPacket(eth_payload, 12, eth_payload.length-12);
            // System.out.println("ip src/" + ipPacket4.getHeader().getSrcAddr());
            // System.out.println("ip dst/" + ipPacket4.getHeader().getDstAddr());
            // fw.write("ip src/"+ ipPacket4.getHeader().getSrcAddr() + "\n");
            // fw.write("ip dst/"+ ipPacket4.getHeader().getDstAddr() + "\n");
            UdpPacket udpPacket = ipPacket4.get(UdpPacket.class);
            // System.out.println("src port/" + udpPacket.getHeader().getSrcPort());
            // System.out.println("dst port/"+udpPacket.getHeader().getDstPort());
            // fw.write("src port/"+udpPacket.getHeader().getSrcPort() + "\n");
            // fw.write("dst port/"+udpPacket.getHeader().getDstPort() + "\n");
            DnsPacket dnsPacket = ipPacket4.get(DnsPacket.class);
            List<DnsQuestion> gq = dnsPacket.getHeader().getQuestions();
            for (int i=0;i<gq.size();i++) {
              System.out.println(gq.get(i).getQName().getName());
              // fw.write(gq.get(i).getQName() + "\n");
              p.getDomain().add(gq.get(i).getQName() + "");
              //fw.write("," + gq.get(i).getQName().getName() + "\n" );
            }
            List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
            for(int i=0; i<ga.size();i++ ){
              DnsRData a = ga.get(i).getRData();
              if (a.getClass()==DnsRDataA.class) {
                DnsRDataA aDataA = (DnsRDataA)a;
                System.out.println("addr/"+aDataA.getAddress());
                p.getIp_addr().add(aDataA.getAddress() + "");
                // fw.write(",,"+ aDataA.getAddress()+ "\n" );
              }
              // if (a.getClass()==DnsRDataCName.class){
                //   DnsRDataCName aDataCName = (DnsRDataCName)a;
                //   System.out.println(aDataCName.getCName().getName());
                
              // }
            }
            System.out.println("IPv4");
            p.setIp_type("IPv4");
            // fw.write(",,,"+"IPv4"+"\n");
          }
          
          // for (int i=0;i<gq.size();i++) {
          //   System.out.println(gq.get(i).getQName());
          // }
          // List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
          // for(int i=0; i<ga.size();i++ ){
          //   DnsRData a = ga.get(i).getRData();
          //   if (a.getClass()==DnsRDataA.class) {
          //     DnsRDataA aDataA = (DnsRDataA)a;
          //     System.out.println("addr/"+aDataA.getAddress());
          //   }
          //   // if (a.getClass()==DnsRDataCName.class){
          //   //   DnsRDataCName aDataCName = (DnsRDataCName)a;
          //   //   System.out.println(aDataCName.getCName().getName());
              
          //   // }
          // }
          // System.out.println(ga);
          if(ByteArrays.getInt(eth_payload, 2,2)==0x8864){
            // System.out.println("vlan type 8864");
          }
          // DnsPacket dnsPacket = packet.get(DnsPacket.class);
          // System.out.println("ip src" + ipPacket3.getHeader().getSrcAddr());
          // System.out.println("ip dst"+ ipPacket3.getHeader().getDstAddr());
          // System.out.println(ipPacket3.getHeader().getProtocol());
          // UdpPacket udpPacket = packet.get(UdpPacket.class);
          // System.out.println(udpPacket);
          // System.out.println(ByteArrays.toHexString(ipBytes,":"));
          // byte[] ipBytes1 = ethernetPacket.getPayload().getRawData();
          // System.out.println(ByteArrays.toHexString(ipBytes1,":"));
          
          // System.out.println(ipV6Packet.getHeader().getSrcAddr());
          // System.out.println(ipPacket2.getHeader().getSrcAddr());
        } catch (Exception e) {
          e.printStackTrace();
        }
        // try {
        //   if (ipPacket != null){
        //     System.out.println("ip src/" + ipPacket.getHeader().getSrcAddr().getHostAddress()); // get src ipv4
        //     System.out.println("ip dst/" + ipPacket.getHeader().getDstAddr().getHostAddress()); // get dst ipv4
        //     System.out.println("protocol/" + ipPacket.getHeader().getProtocol()); // get protocol
            
        //   }
        //   if (ipPacket2 != null){
        //     System.out.println("ip src/" + ipPacket2.getHeader().getSrcAddr().getHostAddress()); // get src ipv6
        //     System.out.println("ip dst/" + ipPacket2.getHeader().getDstAddr().getHostAddress()); // get dst ipv6
        //     System.out.println("protocol/" + ipPacket2.getHeader().getProtocol()); // get protocol
            
        //   }

        //   if (tcpPacket != null){
        //     System.out.println("source port/"+ tcpPacket.getHeader().getSrcPort());
        //     System.out.println("destination port/"+ tcpPacket.getHeader().getDstPort());
        //   }
        //   if (udpPacket != null){
        //     System.out.println( "source port/"+udpPacket.getHeader().getSrcPort());
        //     System.out.println( "destination port/"+udpPacket.getHeader().getDstPort());
        //   }
        //   if (dnsPacket != null){
        //     // System.out.println(dnsPacket.getHeader().getQuestions());
        //     List<DnsQuestion> gq = dnsPacket.getHeader().getQuestions();
        //     for(int i=0;i<gq.size();i++){
        //       System.out.println(gq.get(i).getQName());
        //     }
        //     // System.out.println(dnsPacket.getHeader().getAnswers());
        //     List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
        //     for (int i=0;i<ga.size();i++) {
        //       DnsRData a = ga.get(i).getRData();
        //       if(a.getClass()==DnsRDataA.class){
        //         DnsRDataA aData=(DnsRDataA)a;
        //         System.out.println("ip addr"+aData.getAddress());
        //       }
              
        //       if (a.getClass()==DnsRDataCName.class){
        //         DnsRDataCName aDataCName = (DnsRDataCName)a;
        //         System.out.println("cname/"+aDataCName.getCName().getName());
        //       }
        //       // System.out.println(ga.get(i).getName().getName());
        //       // System.out.println(a);
        //     }
        //     // System.out.println(ga);
        //     // DnsPacket dnsPacket2 = DnsPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
        //     // byte[] ipBytes = dnsPacket2.getPayload().getRawData();
        //     // System.out.println(ByteArrays.toHexString(ipBytes,":"));
            
        //     // IpV4Packet ipPacket2= IpV4Packet.newPacket(ipBytes,0,ipBytes.length);
        //     // System.out.println(dnsPacket);
            
        //     // System.out.println(dnsPacket2.getRawData());
        //   }

        // } catch (Exception e) {
        //   e.printStackTrace();
        // }
      }
      // public int length() {
      //   return qName.length();
      // }
      
    };
    
    // public int length() {
    //   DnsDomainName qName;
    //   return qName.length() + SHORT_SIZE_IN_BYTES * 2;
    // }
    // InetAddress[] machines = InetAddress.getAllByName("yahoo.com");
    // for(InetAddress address : machines){
    // System.out.println(address.getHostAddress());
    // }

    // PacketListener listener = new PacketListener() {
    // @Override
    // public void gotPacket(Packet packet) {
    // System.out.println(handle.getTimestamp());
    // System.out.println(packet);
    // }
    // };

    try {
      handle.loop(COUNT, listener);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    // PcapStat ps = handle.getStats();
    // System.out.println("ps_recv: " + ps.getNumPacketsReceived());
    // System.out.println("ps_drop: " + ps.getNumPacketsDropped());
    // System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
    // if (Platform.isWindows()) {
    // System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
    // }
    handle.close();
    writeToFile();
  //   if( new TrafficDAO().addListTraffic(trafficArrayList)){
  //     try {
  //         System.out.println("Write to db successfully");
  //         ArrayList<Traffic15p> tr = new TrafficDAO().getTraffic15p();
  //         FileWriter myWriter = new FileWriter("out.csv");
  //         for(int j =0 ; j<tr.size()-1;j++) {
  //             myWriter.write(EthernetPacket);
  //             myWriter.write("\n");


  //             // add and update to database
  //             //    boolean boo = new TrafficDAO().addTraffic(trafficArrayList.get(j));
  //             //    System.out.println(boo);
  //         }
  //         myWriter.close();
  //         System.out.println("Successfully wrote to the file.");
  //     } catch (Exception e) {
  //         System.out.println("An error occurred.");
  //         e.printStackTrace();
  //     }
  //   }
  }
}
