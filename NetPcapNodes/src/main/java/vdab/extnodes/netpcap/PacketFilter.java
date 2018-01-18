package vdab.extnodes.netpcap;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;

public class PacketFilter {
	private String c_Source;
	private byte[] c_ByteSource;
	private String c_Dest;
	private byte[] c_ByteDest;
	private String c_Address;
	private byte[] c_ByteAddress;
	private Integer c_Protocol;
	private int c_IntProtocol;
	private String c_Error;
	private String c_Match;
	private Ip4 c_Ip4Header = new Ip4();
	public void setProtocol(Integer protocol){
		c_Protocol = protocol;
		c_IntProtocol = c_Protocol.intValue();
	}
	public Integer getProtocol(){
		return c_Protocol;
	}
	public void setAddress(String addr){
		c_Address = addr;
		try {
			c_ByteAddress = InetAddress.getByName(addr).getAddress();
		} 
		catch (UnknownHostException e) {
			c_Error = "Unknown address e>"+e;
			c_Address = null;
		}
	}
	public String getAddress(){
		return c_Address;
	}
	public void setSource(String source){
		c_Source = source;
		try {
			c_ByteSource = InetAddress.getByName(source).getAddress();
		} 
		catch (UnknownHostException e) {
			c_Error = "Unknown source e>"+e;
			c_Source = null;
		}
	}
	public String getSource(){
		return c_Source;
	}
	public void setDest(String dest){
		c_Dest = dest;

		try {
			c_ByteDest = InetAddress.getByName(dest).getAddress();
		} 
		catch (UnknownHostException e) {
			c_Error = "Unknown destination e>"+e;
			c_Dest = null;
		}
	}
	public String getDest(){
		return c_Dest;
	}
	public boolean passesProtocol(Ip4 ip4Header, PcapPacket packet){
		if (c_Protocol != null) {
			if (!PcapUtility.isProtocol(c_Protocol, packet))
				return false;
		}	
		return true;
		
	}
	public boolean passesFilter(PcapPacket packet){
		// Check for matching protocol
		if (c_Protocol != null) {
			if (!PcapUtility.isProtocol(c_Protocol, packet))
				return false;
		}	
		
		if (c_Source == null && c_Dest == null && c_Address == null)
			return true;
		
		if(packet.hasHeader(c_Ip4Header)) {
			byte[] source = c_Ip4Header.source();
			byte[] dest = c_Ip4Header.destination();
			// Check for source
			if (c_Source != null){	
				if (!PcapUtility.isSameIp4Address(c_ByteSource, source))
					return false;
			}
			// Check for dest
			if (c_Dest != null){
				if (!PcapUtility.isSameIp4Address(c_ByteDest, dest))
					return false;
			}
			// Check for dest
			if (c_Address != null){
				if (!PcapUtility.isSameIp4Address(c_ByteAddress, dest) && !PcapUtility.isSameIp4Address(c_ByteAddress, source))
					return false;
			}
		}
		return true;

	}
	public void setMatch(String match) {
		c_Match = match;		
	}
	public String getMatch() {
		return c_Match ;		
	}

}