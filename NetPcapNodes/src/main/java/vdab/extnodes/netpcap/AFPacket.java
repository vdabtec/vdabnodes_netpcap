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

import java.util.Date;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import com.lcrc.af.AnalysisCompoundData;
import com.lcrc.af.AnalysisData;

public class AFPacket {
	private final static String PACKET_RECORD = "Packet";

	private long c_PacketTime;
	private String c_Source;
	private String c_Dest;
	private String c_Protocol;
	private String c_Content;
	
	private Ip4 c_Ip4Header = new Ip4();
	private Tcp c_TcpHeader = new Tcp();


	public AFPacket(PcapPacket packet){
		this (packet, 80);
	}
	public AFPacket(PcapPacket packet, int maxLen){
		c_Protocol = PcapUtility.getStaticLastHeader(packet).getName();
		c_PacketTime = packet.getCaptureHeader().timestampInMillis();
		if(packet.hasHeader(c_Ip4Header)) {
			c_Source = PcapUtility.getAddress(c_Ip4Header.source());
			c_Dest = PcapUtility.getAddress(c_Ip4Header.destination());
		}
		if (packet.hasHeader(c_TcpHeader)){
			int hlen = c_TcpHeader.hlen();   
			int offset = c_TcpHeader.getPayloadOffset();
			int len  = c_TcpHeader.getPayloadLength();
        	final boolean hasMore = ((c_Ip4Header.flags() & Ip4.FLAG_MORE_FRAGMENTS) != 0) ;
			final int caplen = packet.getCaptureHeader().caplen();
			if ((len - offset) > 0){
				String content = packet.getUTF8String(offset, len);
				int gotLen = content.length();		
				if (gotLen > 0 &&  maxLen > 0){
					c_Content = content.substring(0, Math.min(gotLen-1, maxLen));
				}
			}
		}
	}
	public String getProtocol(){
		return c_Protocol;
	}
	public String getSource(){
		return c_Source;
	}
	public String getDest(){
		return c_Dest;
	}
	public long getTimestamp(){
		return c_PacketTime;
	}
	public AnalysisData getAnalysisData(){
		AnalysisCompoundData acd = new AnalysisCompoundData(PACKET_RECORD );
		if (c_PacketTime != 0L)
			acd.addAnalysisData("Timestamp", c_PacketTime);
		if (c_PacketTime != 0L)
			acd.addAnalysisData("Time", new Date(c_PacketTime));
		if (c_Protocol != null)
			acd.addAnalysisData("Protocol", c_Protocol);
		if (c_Source != null)
			acd.addAnalysisData("Source", c_Source);
		if (c_Source != null)
			acd.addAnalysisData("Dest", c_Dest);
		if (c_Content != null)
			acd.addAnalysisData("Content", c_Content);
		return acd;			
	}


}
