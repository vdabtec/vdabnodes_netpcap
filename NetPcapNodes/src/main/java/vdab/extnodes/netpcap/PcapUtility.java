package vdab.extnodes.netpcap;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import com.lcrc.af.AnalysisObject;
import com.lcrc.af.constants.IPProtocolType;
import com.lcrc.af.datatypes.AFEnum;


public class PcapUtility {
	public static final Ip4 IP4 = new Ip4();
	public static final Tcp TCP = new Tcp();
	public static final Udp UDP = new Udp();
	public static final Http HTTP = new Http();
	public static final AFEnum s_IPProtocolTypeEnum = IPProtocolType.getEnum();
	
	public static List<PcapIf> getNetworkDevices(){		
		List<PcapIf> allDevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
        int ret = Pcap.findAllDevs(allDevs, errbuf);  
        if (ret == Pcap.NOT_OK || allDevs.isEmpty()) {  
            AnalysisObject.logError("PcapUtility.getNetworkDevices()","Can't read list of devices, error is "+ errbuf.toString());  
            return null;  
        }  
        return allDevs;
 	}
	public static boolean isSameIp4Address (byte[] addr1, byte[] addr2){
		if (addr1.length < 4 || addr2.length < 4)
			return false;
		
		for (int n = 0; n < 4; n++){
			if (addr1[n] != addr2[n])
				return false;
		}
		return true;
		
	}
	public static String getProtocol (PcapPacket packet){
		
		 if (packet.hasHeader(HTTP))
			 return s_IPProtocolTypeEnum.getLabel(IPProtocolType.HTTP);
	
		 if (packet.hasHeader(TCP))
			 return s_IPProtocolTypeEnum.getLabel(IPProtocolType.TCP);
	

		 if (packet.hasHeader(UDP))
			 return s_IPProtocolTypeEnum.getLabel(IPProtocolType.UDP);
		 
		 return "???";
	}

	public static String getAddress(byte[] byteAddr){
		try {
			return InetAddress.getByAddress(byteAddr).getHostAddress();
		} catch (UnknownHostException e) {
			return "???";
		} 
	}
	public static boolean isProtocol (int protocol, PcapPacket packet){
	
		// DO NOT SUPPORT IP6 FOR HIGHER PROTOCOLS
		boolean hasIP4 = packet.hasHeader(IP4);
		
		switch (protocol){
		case IPProtocolType.TCP:
			return packet.hasHeader(TCP) && hasIP4;
		
		case IPProtocolType.UDP:
			return packet.hasHeader(UDP) && hasIP4;
			
		case IPProtocolType.HTTP:
			return packet.hasHeader(HTTP) && hasIP4;
			
		case IPProtocolType.ALL:
			return true;

		}
		return false;
	}
	public static StringBuilder getPacketHeaderInfo(PcapPacket packet){
;
		StringBuilder sb = new StringBuilder();
	  	sb.append(new Date(packet.getCaptureHeader().timestampInMillis()));
		sb.append(" > ");
		if (packet.hasHeader(IP4)){
			Ip4 ip4Header = packet.getHeader(new Ip4());
			sb.append(getAddress(ip4Header.source()));
			sb.append(" > ");
			sb.append(getAddress(ip4Header.destination()));
			sb.append(" > ");
		}
		sb.append(getStaticLastHeader(packet).getName());
		sb.append("-");
		sb.append(getProtocol(packet));
		sb.append(" > ");
		sb.append(packet.getCaptureHeader().caplen());
		return sb;
	}
	  public static JHeader getStaticLastHeader(JPacket packet) {  
	        return getStaticLastHeader(packet, false);   
	    }  
	      
	    public static JHeader getStaticLastHeader(JPacket packet, boolean payloadOk) {  
	        int last = packet.getState().getHeaderCount() - 1;  
	        if (!payloadOk && packet.getState().getHeaderIdByIndex(last) == Payload.ID  
	            && last > 0) {  
	            last--; // We want the last header before payload  
	        }  
	      
	        final JHeader header =  
	            JHeaderPool.getDefault().getHeader(packet.getState().getHeaderIdByIndex(last));  
	        packet.getHeaderByIndex(last, header);  
	      
	        return header;  
	    }  

}
