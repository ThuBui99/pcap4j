package com.test.pcap4j;

import java.io.FileWriter;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.PreparedStatement;
// import java.util.ArrayList;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.util.ByteArrays;

@SuppressWarnings("javadoc")
public class Loop {

  private static final String COUNT_KEY = Loop.class.getName() + ".count";
  private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);// 8445

  private static final String READ_TIMEOUT_KEY = Loop.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = Loop.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes] //65536
  protected static FileWriter fw;
  protected static List<TikTokPacket> listPacket = new ArrayList<TikTokPacket>();

  private Loop() {
  }

  // private static void writeToFile() {
  // try {
  // fw = new FileWriter("out.csv");
  // fw.write("mac_client, domain, ip, ip_type \n");
  // } catch (IOException e) {
  // e.printStackTrace();
  // try {
  // fw.close();
  // } catch (IOException e1) {
  // // TODO Auto-generated catch block
  // e1.printStackTrace();
  // }
  // }

  // for (TikTokPacket tikTokPacket : listPacket) {
  // int rowNum = Math.max(tikTokPacket.getDomain().size(),
  // tikTokPacket.getIp_addr().size());

  // for (int i = 0; i < rowNum; i++) {
  // String macClient, domain, ip, ip_type;
  // if (i == 0)
  // macClient = tikTokPacket.getMac_client();
  // // else
  // // macClient = "";
  // if (i < tikTokPacket.getDomain().size())
  // domain = tikTokPacket.getDomain().get(i);
  // // else
  // // domain = "";
  // if (i < tikTokPacket.getIp_addr().size())
  // ip = tikTokPacket.getIp_addr().get(i);
  // else
  // ip = "";
  // if (i == 0)
  // ip_type = tikTokPacket.getIp_type();
  // else
  // ip_type = "";
  // try {
  // fw.write(macClient + "," + domain + "," + ip + "," + ip_type + "\n");
  // } catch (IOException e) {
  // // TODO Auto-generated catch block
  // e.printStackTrace();
  // }
  // }
  // }
  // try {
  // fw.close();
  // } catch (IOException e) {
  // // TODO Auto-generated catch block
  // e.printStackTrace();
  // }
  // }

  private static void writeToFile() {
    try {
      fw = new FileWriter("out.csv");
      fw.write("mac_client, domain, ip, ip_type \n");
    } catch (IOException e) {
      e.printStackTrace();
      try {
        fw.close();
      } catch (IOException e1) {
        // TODO Auto-generated catch block
        e1.printStackTrace();
      }
    }

    for (TikTokPacket tikTokPacket : listPacket) {
      int rowNum = tikTokPacket.getIp_addr().size();
      String macClient, domain, ip, ip_type;
      macClient = tikTokPacket.getMac_client();
      domain = tikTokPacket.getDomain();
      ip_type = tikTokPacket.getIp_type();

      for (int i = 0; i < rowNum; i++) {
        ip = tikTokPacket.getIp_addr().get(i);
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

  // public static Object object = new Object();
  private static String filepath;

  public static ArrayList<TikTokPacket> docfile(String filepath, String filter) throws NotOpenException {
    ArrayList<TikTokPacket> lisTikTokPackets = new ArrayList<TikTokPacket>();
    try {
      PcapHandle handle = Pcaps.openOffline(filepath);
      // String filter = args.length != 0 ? args[0] : "";

      if (filter.length() != 0) {
        handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
      }

      PacketListener listener = new PacketListener() {

        public void gotPacket(Packet packet) {
          EthernetPacket ethernetPacket0 = packet.get(EthernetPacket.class);

          // System.out.println(handle.getTimestamp());
          TikTokPacket tp = new TikTokPacket();
          tp.setMac_client(ethernetPacket0.getHeader().getDstAddr() + "");

          try {
            EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getRawData(), 0,
                packet.getRawData().length);
            byte[] eth_payload = ethernetPacket.getPayload().getRawData();
            if (ByteArrays.getInt(eth_payload, 10, 2) == 0x0057) {
              IpPacket ipPacket3 = IpV6Packet.newPacket(eth_payload, 12, eth_payload.length - 12);
              UdpPacket udpPacket = ipPacket3.get(UdpPacket.class);
              DnsPacket dnsPacket = ipPacket3.get(DnsPacket.class);
              List<DnsQuestion> gq = dnsPacket.getHeader().getQuestions();

              tp.setDomain(gq.get(0).getQName() + "");

              // for (int i = 0; i < gq.size(); i++) {
              // System.out.println(gq.get(i).getQName().getName());
              // tp.getDomain().add(gq.get(i).getQName() + "");
              // // tp.getDomain()
              // }
              List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
              for (int i = 0; i < ga.size(); i++) {
                DnsRData a = ga.get(i).getRData();
                if (a.getClass() == DnsRDataA.class) {
                  DnsRDataA aDataA = (DnsRDataA) a;
                  System.out.println("addr/" + aDataA.getAddress());
                  tp.getIp_addr().add(aDataA.getAddress() + "");
                }
                // if (a.getClass()==DnsRDataCName.class){
                // DnsRDataCName aDataCName = (DnsRDataCName)a;
                // System.out.println(aDataCName.getCName().getName());

                // }
              }
              System.out.println("IPv6");
              tp.setIp_type("IPv6");
              listPacket.add(tp);
            }
            if (ByteArrays.getInt(eth_payload, 10, 2) == 0x0021) {
              IpPacket ipPacket4 = IpV4Packet.newPacket(eth_payload, 12, eth_payload.length - 12);
              UdpPacket udpPacket = ipPacket4.get(UdpPacket.class);
              DnsPacket dnsPacket = ipPacket4.get(DnsPacket.class);
              List<DnsQuestion> gq = dnsPacket.getHeader().getQuestions();
              tp.setDomain(gq.get(0).getQName() + "");
              // for (int i = 0; i < gq.size(); i++) {
              // System.out.println(gq.get(i).getQName().getName());
              // // tp.getDomain().add(gq.get(i).getQName() + "");
              // }
              List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
              for (int i = 0; i < ga.size(); i++) {
                DnsRData a = ga.get(i).getRData();
                if (a.getClass() == DnsRDataA.class) {
                  DnsRDataA aDataA = (DnsRDataA) a;
                  System.out.println("addr/" + aDataA.getAddress());
                  tp.getIp_addr().add(aDataA.getAddress() + "");
                }
                // if (a.getClass()==DnsRDataCName.class){
                // DnsRDataCName aDataCName = (DnsRDataCName)a;
                // System.out.println(aDataCName.getCName().getName());

                // }
              }
              System.out.println("IPv4");
              tp.setIp_type("IPv4");
              listPacket.add(tp);
            }
            if (ByteArrays.getInt(eth_payload, 2, 2) == 0x8864) {
              // System.out.println("vlan type 8864");
            }
          } catch (Exception e) {
            e.printStackTrace();
          }
        }
      };
      try {
        handle.loop(COUNT, listener);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
      handle.close();
      writeToFile();
    } catch (PcapNativeException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return lisTikTokPackets;
  }

  public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {

    String filter = args.length != 0 ? args[0] : "";

    System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println("\n");
    // final PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS,
    // READ_TIMEOUT);
    System.out.println("Start");
    // Creating a File object for directory
    // List of all files and directories
    File directoryPath = new File("1");
    File fileList[] = directoryPath.listFiles();
    for (File file : fileList) {
      docfile(file.getPath(), filter);
    }

    // final PcapHandle handle =
    // Pcaps.openOffline("1\\dns_00001_20220505090359.pcap");

    // if (filter.length() != 0) {
    // handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
    // }

    // PacketListener listener = new PacketListener() {

    // public void gotPacket(Packet packet) {
    // EthernetPacket ethernetPacket0 = packet.get(EthernetPacket.class);

    // // System.out.println(handle.getTimestamp());
    // TikTokPacket tp = new TikTokPacket();
    // tp.setMac_client(ethernetPacket0.getHeader().getDstAddr() + "");

    // try {
    // EthernetPacket ethernetPacket = EthernetPacket.newPacket(packet.getRawData(),
    // 0, packet.getRawData().length);
    // byte[] eth_payload = ethernetPacket.getPayload().getRawData();
    // if (ByteArrays.getInt(eth_payload, 10, 2) == 0x0057) {
    // IpPacket ipPacket3 = IpV6Packet.newPacket(eth_payload, 12, eth_payload.length
    // - 12);
    // UdpPacket udpPacket = ipPacket3.get(UdpPacket.class);
    // DnsPacket dnsPacket = ipPacket3.get(DnsPacket.class);
    // List<DnsQuestion> gq = dnsPacket.getHeader().getQuestions();
    // for (int i = 0; i < gq.size(); i++) {
    // System.out.println(gq.get(i).getQName().getName());
    // tp.getDomain().add(gq.get(i).getQName() + "");
    // }
    // List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
    // for (int i = 0; i < ga.size(); i++) {
    // DnsRData a = ga.get(i).getRData();
    // if (a.getClass() == DnsRDataA.class) {
    // DnsRDataA aDataA = (DnsRDataA) a;
    // System.out.println("addr/" + aDataA.getAddress());
    // tp.getIp_addr().add(aDataA.getAddress() + "");
    // }
    // // if (a.getClass()==DnsRDataCName.class){
    // // DnsRDataCName aDataCName = (DnsRDataCName)a;
    // // System.out.println(aDataCName.getCName().getName());

    // // }
    // }
    // System.out.println("IPv6");
    // tp.setIp_type("IPv6");
    // listPacket.add(tp);
    // // fw.write(",,,"+"IPv6" +"\n");
    // }
    // if (ByteArrays.getInt(eth_payload, 10, 2) == 0x0021) {
    // IpPacket ipPacket4 = IpV4Packet.newPacket(eth_payload, 12, eth_payload.length
    // - 12);
    // UdpPacket udpPacket = ipPacket4.get(UdpPacket.class);
    // DnsPacket dnsPacket = ipPacket4.get(DnsPacket.class);
    // List<DnsQuestion> gq = dnsPacket.getHeader().getQuestions();
    // for (int i = 0; i < gq.size(); i++) {
    // System.out.println(gq.get(i).getQName().getName());
    // tp.getDomain().add(gq.get(i).getQName() + "");
    // }
    // List<DnsResourceRecord> ga = dnsPacket.getHeader().getAnswers();
    // for (int i = 0; i < ga.size(); i++) {
    // DnsRData a = ga.get(i).getRData();
    // if (a.getClass() == DnsRDataA.class) {
    // DnsRDataA aDataA = (DnsRDataA) a;
    // System.out.println("addr/" + aDataA.getAddress());
    // tp.getIp_addr().add(aDataA.getAddress() + "");
    // }
    // // if (a.getClass()==DnsRDataCName.class){
    // // DnsRDataCName aDataCName = (DnsRDataCName)a;
    // // System.out.println(aDataCName.getCName().getName());

    // // }
    // }
    // System.out.println("IPv4");
    // tp.setIp_type("IPv4");
    // listPacket.add(tp);
    // }
    // if (ByteArrays.getInt(eth_payload, 2, 2) == 0x8864) {
    // // System.out.println("vlan type 8864");
    // }
    // } catch (Exception e) {
    // e.printStackTrace();
    // }
    // }
    // };

    // public int length() {
    // DnsDomainName qName;
    // return qName.length() + SHORT_SIZE_IN_BYTES * 2;
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

    // try {
    // handle.loop(COUNT, listener);
    // } catch (InterruptedException e) {
    // e.printStackTrace();
    // }
    // PcapStat ps = handle.getStats();
    // System.out.println("ps_recv: " + ps.getNumPacketsReceived());
    // System.out.println("ps_drop: " + ps.getNumPacketsDropped());
    // System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
    // if (Platform.isWindows()) {
    // System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
    // }
    // handle.close();
    // writeToFile();

    // select/insert database
    TikTokPacket tikTokPacket = new TikTokPacket();
    // tikTokPacket = new TikTokPacketDAO().searchTikTokPacket().get(0);
    // System.out.println(tikTokPacket.getMac_client() +"," + tikTokPacket.getDomain() +","+ tikTokPacket.getIp_addr() +"," + tikTokPacket.getIp_type());
    tikTokPacket.setMac_client("a0:65:18:74:fc:23");
    tikTokPacket.setDomain("www.google.com");
    tikTokPacket.setIp_type("IPv4");
    // tikTokPacket.setIp_addr(ip_addr);
    boolean boo = new TikTokPacketDAO().addTikTokPacket(tikTokPacket);
    System.out.println(boo);
    boolean boo2 = new TikTokPacketDAO().addListTikTokPacket((List<TikTokPacket>) tikTokPacket);
  }
}
