/*LICENSE*
 * Copyright (C) 2013 - 2018 MJA Technology LLC 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
package vdab.extnodes.netpcap;

import java.util.ArrayList;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import com.lcrc.af.datatypes.LogMessage;
import com.lcrc.af.util.ControlDataBuffer;
import com.lcrc.af.util.StringUtility;

public class NetworkTap_Thread implements Runnable{
	
	public static final Ip4 ip4Header = new Ip4();
	public static final Tcp tcpHeader = new Tcp();
	public static final Udp UDP = new Udp();
	public static final Http HTTP = new Http();
	
	private boolean c_StopNow = false;
	private PacketFilter c_PacketFilter ;

	private NetworkTapRequestor c_TapRequestor;
	private Pcap c_Pcap;
	private int c_DeviceNo  = 0;
	private boolean c_Reset ;
	private Thread c_ExeThread; 
	private ControlDataBuffer c_SourceAddresses = new ControlDataBuffer("SourceAddresses"); 
	private ControlDataBuffer c_DestAddresses = new ControlDataBuffer("DestAddresses"); 

	public interface NetworkTapRequestor {
		public void handlePacket(String packet);
		public void handlePacket(AFPacket packet);
		public LogMessage setError(String error);
		public String getThreadLabel();
		public String getDeviceName();
		public PacketFilter getPacketFilter();
		public int getContentLength();
		public boolean isLearning();
	}
	public NetworkTap_Thread(NetworkTapRequestor requestor) {
		c_TapRequestor = requestor;
		c_ExeThread = new Thread(this, c_TapRequestor.getThreadLabel());
		c_ExeThread.start();
		
	}
	public void requestBufferReset(){
		c_Reset = true;
	}
	public boolean shouldReset(){
		return c_Reset;
	}
	public void resetBuffers(){
		c_Reset = false;
		c_SourceAddresses.clear();
		c_DestAddresses.clear();
	}
		
	public String[] getAllAddresses(){
		ArrayList<String> l = new ArrayList<String>();
		String[] srcs = c_SourceAddresses.getAllSet();
		String[] dests = c_DestAddresses.getAllSet();
		for (String src: srcs)
			l.add(src);
		for (String dest: dests){
			if (!l.contains(dest))
				l.add(dest);
		}
		return l.toArray(new String[l.size()]);
	}
	public void waitForCommand() throws InterruptedException{
		c_ExeThread.join();
	}
	public void stop(){
		if (c_Pcap  != null){
			c_Pcap.breakloop();
			c_Pcap.close();
		}
		c_StopNow = true;
	}
	public void run() {	
		StringBuilder sbErr = new StringBuilder();			
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
         if (c_TapRequestor.getDeviceName() == null){
        	c_TapRequestor.setError("Unable to find any network devices");
        	return;
        }
        c_Pcap = Pcap.openLive(c_TapRequestor.getDeviceName(), snaplen, flags, timeout, sbErr); 
        
        PcapPacketHandler<NetworkTapRequestor> afPacketHandler = new PcapPacketHandler<NetworkTapRequestor>() {  
        	PacketFilter c_Filter;
         	public void nextPacket(PcapPacket packet, NetworkTapRequestor requestor) {
         		
        		// Get packet filter
        		c_Filter = requestor.getPacketFilter();   
        
        		// Reset buffers when requested previouly by source.
        		if (shouldReset())
        			resetBuffers();
        		
        		StringBuilder sb =  PcapUtility.getPacketHeaderInfo(packet); 
        		if (!c_Filter.passesFilter( packet))
        			return;

        		if (packet.hasHeader(ip4Header)){
        			//Record addresses when in the learning mode.
        			if (requestor.isLearning()){
        				if (c_Filter.passesProtocol(ip4Header, packet)){
        					byte[] source = ip4Header.source();
        					byte[] dest = ip4Header.destination();
        					if(source != null){
        						String srcStr = PcapUtility.getAddress(source);
        						c_SourceAddresses.set(srcStr);
        					}
        					if(dest != null){
        						String destStr = PcapUtility.getAddress(dest);
        						c_DestAddresses.set(destStr);
        					}
        				}
        			}
        			/****** TCP and IP4 Header INFO ************************************************
            	final int hlen = ip4Header.hlen() * 4;
            	final int len = ip4Header.length() - hlen;
            	final int packetOffset = ip4Header.getOffset() + hlen;
            	final int dgramOffset = ip4Header.offset() * 8;
            	final boolean hasMore = ((ip4Header.flags() & Ip4.FLAG_MORE_FRAGMENTS) != 0) ;

            	    Protocol           Size        Description
				Ethernet protocol    14 byte    2 MAC adresses (6 byte), Protocoll type (2 byte)
				Internet protocol    20 byte    The default header size
      				  TC protocol    32 byte    The default header size (20 byte) + options (12 byte)
				_____________________________________________________________________________________
            	Total               66 byte
       			without EP          52 byte    (Probably the size the OP is talking about)
 				without EP, Opts    40 byte    (The size talked about in the comments)
        			 *******************************************************************************/
     
          			if (packet.hasHeader(tcpHeader)){
        				int hlen = tcpHeader.hlen();   
        				int offset = tcpHeader.getPayloadOffset();
        				int len  = tcpHeader.getPayloadLength();
  //      				int offset = ip4Header.getPayloadOffset()+hlen*4; 
  //      				int len    = ip4Header.getPayloadLength()-hlen*4;
        	        	final boolean hasMore = ((ip4Header.flags() & Ip4.FLAG_MORE_FRAGMENTS) != 0) ;
        				final int caplen = packet.getCaptureHeader().caplen();

        				if ((len - offset) > 0){
        					String content = packet.getUTF8String(offset, len);
  //      					String content = packet.toHexdump();

        					// If it requires a match - get out if it does not match
        					String match = c_Filter.getMatch();
        					if (match != null && content.indexOf(match) < 0)
        						return;

        					int gotLen = content.length();
        					int maxLen = requestor.getContentLength();
        					
        					ArrayList<String> ids = StringUtility.locateAllBetween(content,"<div id=\"", "\"");
        					if (ids.size() > 0){
        						StringBuilder sb2 = new StringBuilder();
        						for (String id: ids){
            						sb2.append(id).append(".");
        						}
        						sb.append(" IDS="+sb2.toString());
        					
        					}
        					if (gotLen > 0 &&  maxLen > 0){
        						sb.append("\n"+content.substring(0, Math.min(gotLen-1, maxLen)));
        						//			Should be a transition between main claim counts.
        						//          <div id="mainContent"><div id="DashboardClaimCount" class="content">
        						//     			int pos = content.indexOf("<div id=\"mainContent\">");
        						//     			if (pos > 0)
        						//     				sb.append("\n \t >>>>> "+content.substring(pos+21,pos+60));
        					}
        				}
        				// Gets port info.

        				sb.append("\nSEQ="+tcpHeader.seq());
        				int destPort = tcpHeader.destination();	// PORTS are in the UDP and TCP headers - not the IP
        				int sourcePort = tcpHeader.source();          	
        			}
        		}
        		requestor.handlePacket(new AFPacket(packet, requestor.getContentLength()));
   //     		requestor.handlePacket(sb.toString());
         	}


        };  
       c_Pcap.loop(Pcap.LOOP_INFINITE, afPacketHandler, c_TapRequestor);  
		while(!c_StopNow);
	
	}
}
