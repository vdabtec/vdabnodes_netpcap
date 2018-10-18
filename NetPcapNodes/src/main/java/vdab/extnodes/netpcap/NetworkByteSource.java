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
import java.util.Arrays;
import java.util.HashMap;
import java.util.StringTokenizer;

import com.lcrc.af.AnalysisContainer;
import com.lcrc.af.AnalysisDataDef;
import com.lcrc.af.AnalysisEvent;
import com.lcrc.af.AnalysisObject;
import com.lcrc.af.AnalysisSource;
import com.lcrc.af.constants.IPProtocolType;
import com.lcrc.af.constants.OperatingSystem;
import com.lcrc.af.exe.CommandReplyBuffer;
import com.lcrc.af.exe.ExecuteCommand;
import com.lcrc.af.exe.ExecuteCommandReadBytes;
import com.lcrc.af.exe.CommandByteListener;


public class NetworkByteSource extends  AnalysisSource implements CommandByteListener {
	static {
		IPProtocolType.getEnum();
	}
	private ExecuteCommandReadBytes c_Exe;
	private int c_OS;
	private Integer c_Protocol;
	private Integer c_Port;
	private String c_NetworkDevice;
	private String c_Host;

	private TransportPacket c_CurrentPacket;
	private ArrayList<String> c_NetworkDevices = new ArrayList<String>();

	public class TransportPacket {
		private String c_Time;
		private String c_Source;
		private String c_Destination;
		private String c_Flags;
		private String c_Sequence;
		private boolean c_AckOnly;
		private long c_StartSeq;
		private long c_EndSeq;
		private long c_NoBytes;
		private	int c_ErrNo;
		private StringBuilder c_PacketData;
		private TransportPacket c_HeadPacket;
		public HashMap<String,TransportPacket> c_PacketTransport_map;
		public TransportPacket (Integer os, StringTokenizer st){
				switch (os){
				case OperatingSystem.WINDOWS:
					parseWinDump(st);
					break;
								
				default:	
					parseTcpDump(st);
					break;
			}
		}
		private void parseTcpDump(StringTokenizer st){
			int cnt =0;
			while(st.hasMoreTokens()){
				String next = st.nextToken();
				String nextVal = null;
				switch (cnt){
				case 0:
					c_Time = next;
					break;
					
				case 2:
					c_Source = next;
					break;

				case 3:
					c_Destination = next;
					break;

				case 4:
				case 6:
				case 8:
				case 10:
				case 12:
					nextVal = st.nextToken();
					if (next.equals("Flags")){
						c_Flags = nextVal;
					}
					else if (next.equals("seq")){
						c_Sequence = nextVal;
						parseTcpDumpSequence();
					}

					break;
				}
				cnt++;
				if (nextVal != null)
					cnt++;
			}
			c_AckOnly = (c_Sequence == null);
		}
		private void parseTcpDumpSequence(){
				StringTokenizer st = new StringTokenizer(c_Sequence,":");
				try {
					c_StartSeq 	= Long.parseLong(st.nextToken());
					c_EndSeq 	= Long.parseLong(st.nextToken());
					c_NoBytes = c_EndSeq - c_StartSeq;
				}
				catch (Exception e) {
					c_ErrNo = 6;
				}
		}
				
		private void parseWinDump(StringTokenizer st){
			int cnt =0;
			while(st.hasMoreTokens()){
				String next = st.nextToken();

				switch (cnt){ // WINDUMP
				case 0:
					c_Time = next;
					break;
					
				case 2:
					c_Source = next;
					break;

				case 3:
					c_Destination = next;
					break;

				case 4:
					c_Flags = next;
					break;

				case 5:
					c_AckOnly = (next.equals("ack"));
					if (!c_AckOnly){
						c_Sequence = next;
						parseWinDumpSequence();
					}
				}
				cnt++;
			}
		}
		
		private void parseWinDumpSequence(){
			StringTokenizer st = new StringTokenizer(c_Sequence,":()");
			try {
				c_StartSeq 	= Long.parseLong(st.nextToken());
				c_EndSeq 	= Long.parseLong(st.nextToken());
				c_NoBytes = Integer.parseInt(st.nextToken());
			}
			catch (Exception e) {
				c_ErrNo = 5;
			}
			
		}
		public boolean isHeadPacket(){
			return c_HeadPacket == null;
		}
		public void setHeadPacket(TransportPacket head){
			c_HeadPacket = head;
		}
		public TransportPacket getHeadPacket(){
			if (c_HeadPacket == null)
				return this;
			else
				return c_HeadPacket;
		}
		public boolean isAckOnly(){
			return c_AckOnly;
		}
		public String getSource(){
			return c_Source;
		}
		public String getDestination(){
			return c_Destination;
		}
		public long getNoBytes(){
			return c_NoBytes;
		}
		public boolean isOK(){
			return (c_ErrNo == 0);
		}
		public void addPacketLine(String line){
			getHeadPacket().addPacketLine0(line);
		}
		public void addPacketLine0(String line){
			if(c_PacketData == null){ // FIRST LINE - create buffer
				c_PacketData = new StringBuilder();
				if (line.length() > 40)
					c_PacketData.append(line.substring(40));
				return;
			}
			c_PacketData.append(line);
		}
		public String getKey(){
			StringBuilder sb = new StringBuilder();
			sb.append(c_Source);
			sb.append(">");
			sb.append(c_Destination);
			return sb.toString();
			
		}
		public boolean isSamePacketSet(TransportPacket nextPacket){
			return (getKey().equals(nextPacket.getKey()));
		}
		public String getPacketData(){
			if (c_PacketData == null)
				return null;
			return c_PacketData.toString();
		}
		public String toString(){
			StringBuilder sb = new StringBuilder();
			if (!isOK())
				sb.append("---ERR--->");
			else
				sb.append("--------->");
			
			sb.append(c_Time).append(">");
			sb.append(c_Source).append(">");
			sb.append(c_Destination).append(">");
			sb.append(c_Flags).append(">");
			if (c_AckOnly){
				sb.append("ACKONLY");
			}
			else {
				sb.append(getNoBytes()).append(">");
				if (c_PacketData == null)
					sb.append("null");
				else 
					sb.append(c_PacketData.length());
			}
			
			return sb.toString();
		}
	}
	// ATTRIBUTE Methods
	public Integer get_Port(){
		return c_Port;
	}
	public void set_Port(Integer port){
		c_Port = port;
	}
	public Integer get_Protocol(){
		return c_Protocol;
	}
	public void set_Protocol(Integer protocol){
		c_Protocol = protocol;
	}
	public String get_Host(){
		return c_Host;
	}
	public void  set_Host(String host){
		c_Host = host;
	}
	public String get_NetworkDevice(){
		return c_NetworkDevice;
	}
	public void  set_NetworkDevice(String device){
		c_NetworkDevice = device;
	}
	public AnalysisDataDef def_NetworkDevice(AnalysisDataDef theDataDef){
		if (c_NetworkDevices.size() > 0)
			theDataDef.setAllPickValues(c_NetworkDevices.toArray(new String[c_NetworkDevices.size()]));
		return theDataDef;
	}
	// ANALYSIS NODE Methods
	public void _init(){
		super._init();
		c_OS = AnalysisContainer.getRoot().get_OperatingSystem().intValue();
		getNetworkDevices();
	}
	public void _start(){
		super._start();
		restartMonitoring();
	}
	public void _stop(){
		super._stop();
		if (c_Exe != null)
			c_Exe.stop();
		c_CurrentPacket = null;
	}
	
	// SUPPORTING Methods --------------------------------------
	private void restartMonitoring(){
		if (c_Exe != null )
			c_Exe.stop();
		c_CurrentPacket = null;
		if (isRunning()){
			String cmd = buildCommand();
			AnalysisObject.logTrace("NetworkSource.restartMonitoring()","CMD="+cmd);	
			c_Exe = new ExecuteCommandReadBytes(cmd, 0, 16000, null, this);
		}
	}
	private String buildCommand(){
		StringBuilder sb = new StringBuilder();
		switch (c_OS){
		case OperatingSystem.WINDOWS:
			sb.append("windump ");
			break;
		default:		
			sb.append("tcpdump ");
			break;	
		}
		if (c_NetworkDevice != null){
			try {
				String[] parts = c_NetworkDevice.split("\\.");
				if (parts.length > 0){
					int devno = Integer.parseInt(parts[0]);
					sb.append("-i ").append(devno).append(" ");
				}
			}
			catch (Exception e){
				setError("Unable to parse device number Device="+c_NetworkDevice);
			}
		}
		sb.append("-s 0 -A "); //content in ascii
		if (c_Protocol != null){
			switch (c_Protocol.intValue()){
			case IPProtocolType.TCP:
				sb.append("tcp ");
				break;

			case IPProtocolType.UDP:
				sb.append("udp ");
				break;
			}
		}				
		int noConds = 0;
		// append filter conditions
		if (c_Port != null){
			sb.append("port ");
			sb.append(c_Port);	
			sb.append(" ");
			noConds++;
		}
		
		if (c_Host != null){
			if (noConds > 0)
				sb.append("and ");
			sb.append("host ");
			sb.append(c_Host);	
			sb.append(" ");
			noConds++;
		}
		return sb.toString();
	}
	private void getNetworkDevices(){
		CommandReplyBuffer crb = new CommandReplyBuffer("getNetworkDevices");
		String cmd = null;
		switch (c_OS){
		case OperatingSystem.WINDOWS:
			cmd = "windump -D";
			break;
		default:		
			cmd = "tcpdump -D";
			break;	
		}
		ExecuteCommand ex = new ExecuteCommand(cmd, 0L, 10L, null, crb);
		try {
			ex.waitForCommand();
			c_NetworkDevices.clear();
			int noDevices = 0;
			for (String devLine: crb.getReplyLines()){
				String devLabel = null;
				switch (c_OS){
				case OperatingSystem.WINDOWS:
					StringTokenizer st = new StringTokenizer(devLine,"(");
					st.nextToken();
					String dev = st.nextToken();
					StringBuilder sb = new StringBuilder();
					sb.append(++noDevices);
					sb.append(".");
					sb.append(dev);
					c_NetworkDevices.add(sb.toString());
					break;
					
				default:		
					StringTokenizer st1 = new StringTokenizer(devLine," \t(");
					devLabel = st1.nextToken();
					c_NetworkDevices.add(devLabel);
					break;	
				}
							
			}
		} catch (Exception e) {
			setError("Unable to read network devices e>"+e);
		}
	
	}

	// IMPLEMENT CommandReplyListener
	@Override
	public void handleCommandReply(Object[] params, int noBytes, byte[] bytes) {
		boolean foundCR = false;
		int pos1 = 0;
		int pos2 = 0;
		for (int n = 0; n < noBytes ; n++){
			switch (bytes[n]){
			case 13:
				foundCR = true;
				break;
				
			case 10:
				if (foundCR){				
					byte[] oneLine = Arrays.copyOfRange(bytes, pos1, pos2);
					handleCommandReply0(params, new String(oneLine));
					foundCR = false;
					pos2++;
					pos1 = pos2;
				}
				break;
			
			default:
				
				pos2++;
				break;
			}
		}
			
	
	}
	private void handleCommandReply0(Object[] params, String line) {

			StringTokenizer st = parseIfPacketHeader(line);
			if (st != null){	
				TransportPacket nextPacket = new TransportPacket(c_OS,st);
				if(nextPacket.isAckOnly()){
					; // publish(new AnalysisEvent(this, "ACKONLY",nextPacket.toString()));
				}
				else {
					if (c_CurrentPacket != null){
						if (nextPacket.isSamePacketSet(c_CurrentPacket)){
							nextPacket.setHeadPacket(c_CurrentPacket.getHeadPacket());
						}
						else {
							TransportPacket header = c_CurrentPacket.getHeadPacket();
							if (header.getNoBytes() > 0){
								publish(new AnalysisEvent(this, "PACKET",header.toString()));
								String data = header.getPacketData();
								if (data != null)
									publish(new AnalysisEvent (this, "BODY", data));
							}
							
						}
					}
					c_CurrentPacket = nextPacket;
				}
				
			}

			else  {
				if (c_CurrentPacket != null) {
					c_CurrentPacket.addPacketLine(line);
				}
				else {
					publish(new AnalysisEvent(this, "STRAYBODY",line));
				}
			}	
	
	}
	// Transport layer or??
	private StringTokenizer parseIfPacketHeader(String line){
		String[] lineParts = line.split(">");
		if (lineParts.length != 2 && line.indexOf("ack") < 0)
			return null;
		// WINDUMP
		//09:51:07.670527 IP marks-asus.50365,209.221.9.146.28080: P 3215:4052(837) ack 155247 win 1024			
		// TCPDUMP
		//09:51:07.670527 IP marks-asus.50365,209.221.9.146.28080: Flags [P], seq 3215:4052, ack 155247, win 1024, length 837			
		
		StringTokenizer st = new StringTokenizer(line,"> \t,");
	
		if(st.countTokens() < 9)
			return null;
		return st;
	}
	@Override
	public void handleCommandError(Object[] params, int noBytes, byte[] bytes) {
		// TODO Auto-generated method stub
		
	}
	public void handleCommandFinished(Object[] params, int status) {
		if (isRunning()){
			setError("Command exited early, restarting command");
			restartMonitoring();
		}
	}
	public String getThreadLabel() {
			return "NetworkMonitor";
	}
	
}
