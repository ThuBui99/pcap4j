package com.test.pcap4j;
// package org.pcap4j.sample;

import com.sun.jna.Platform;
import java.io.IOException;
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
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class Loop {

  private static final Class<DnsDomainName> CLAZZ = DnsDomainName.class;
  private static final String COUNT_KEY = Loop.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 34);

  private static final String READ_TIMEOUT_KEY = Loop.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = Loop.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
  protected static DnsDomainName qName;

  private Loop() {
  }

  public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println("\n");

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

    // final PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS,
    // READ_TIMEOUT);
    final PcapHandle handle = Pcaps.openOffline("D:\\pcap1.pcap");

    if (filter.length() != 0) {
      handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
    }

    PacketListener listener = new PacketListener() {

      private DnsDomainName cName;
      public void gotPacket(Packet packet) {

        // TODO Auto-generated method stub
        System.out.println(handle.getTimestamp());

        // System.out.println(packet);
        IpPacket ipPacket = packet.get(IpV4Packet.class);
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        DnsPacket dnsPacket = packet.get(DnsPacket.class);
        System.out.println("source mac      : " + ethernetPacket.getHeader().getSrcAddr());
        System.out.println("destination mac : " + ethernetPacket.getHeader().getDstAddr());
        System.out.println("ip src          : " + ipPacket.getHeader().getSrcAddr().getHostAddress()); // get src addr
        System.out.println("ip dst          : " + ipPacket.getHeader().getDstAddr().getHostAddress()); // get dst addr
        System.out.println("protocol        : " + ipPacket.getHeader().getProtocol()); // get protocol
        try {
          // if (tcpPacket != null){
          //   System.out.println("source port     : "+ tcpPacket.getHeader().getSrcPort());
          //   System.out.println("destination port: "+ tcpPacket.getHeader().getDstPort());
          // }
          // if (udpPacket != null){
          //   System.out.println( "source port     : "+udpPacket.getHeader().getSrcPort());
          //   System.out.println( "destination port: "+udpPacket.getHeader().getDstPort());
          // }
          if (dnsPacket != null){
            // System.out.println(dnsPacket.getHeader().getQuestions());
            List<DnsQuestion> gq = dnsPacket.getHeader().getQuestions();
            for(int i=0;i<gq.size();i++){
              System.out.println(gq.get(i).getQName());
            }
            // System.out.println(dnsPacket.getHeader().getAnswers());
            List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
            for (int i=0;i<ga.size();i++) {
              DnsRData a = ga.get(i).getRData();
              if(a.getClass()==DnsRDataA.class){
                DnsRDataA aData=(DnsRDataA)a;
                System.out.println("ip addr"+aData.getAddress());
              }
              if (a.getClass()==DnsRDataCName.class){
                DnsRDataCName aDataCName = (DnsRDataCName)a;
                System.out.println("cname"+aDataCName.getCName());
              }
              
              // System.out.println(ga.get(i).getRData());
              // System.out.println(a);
            }

            // DnsPacket dnsPacket2 = DnsPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
            // byte[] ipBytes = dnsPacket2.getPayload().getRawData();
            // System.out.println(ByteArrays.toHexString(ipBytes,":"));
            
            // IpV4Packet ipPacket2= IpV4Packet.newPacket(ipBytes,0,ipBytes.length);
            // System.out.println(dnsPacket);
            
            // System.out.println(dnsPacket2.getRawData());
          }

        } catch (Exception e) {
          e.printStackTrace();
        }
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
  }
}
