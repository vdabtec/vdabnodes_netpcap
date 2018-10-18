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

import java.util.List;
import com.lcrc.af.AnalysisDataDef;
import com.lcrc.af.AnalysisEvent;
import com.lcrc.af.AnalysisSource;
import com.lcrc.af.background.BackgroundInit;
import com.lcrc.af.constants.IPProtocolType;
import com.lcrc.af.constants.IconCategory;
import com.lcrc.af.datatypes.AFEnum;
import org.jnetpcap.PcapIf;  

import vdab.extnodes.netpcap.NetworkTap_Thread.NetworkTapRequestor;
  

public class NetworkSource extends  AnalysisSource implements NetworkTapRequestor  {
	static {
		IPProtocolType.getEnum();
	}
	private Integer c_Protocol;
	private Integer c_Port;
	private int c_DeviceNo = 0;
	private String c_Address;
	private String c_Match;
	private PacketFilter c_CurrentFilter;
	private NetworkTap_Thread c_NetworkTap;

	private List<PcapIf> c_NetworkDevices ;
	
	// ATTRIBUTE Methods
	public Integer get_IconCode(){
		return IconCategory.NODE_NET;
	}
	public Integer get_NetworkDevice(){
		return c_DeviceNo;
	}
	public AnalysisDataDef def_Address(AnalysisDataDef theDataDef){
		if (c_NetworkTap != null ){
			String[] allAddresses = c_NetworkTap.getAllAddresses();
			if (allAddresses.length > 0)
				theDataDef.setAllPickValues(allAddresses);
		}
		return theDataDef;
	}
	public void  set_NetworkDevice(Integer device){
		c_DeviceNo = device;
	}
	public Integer get_Port(){
		return c_Port;
	}
	public void set_Port(Integer port){
		c_Port = port;
		c_CurrentFilter = null; // Invalidate filter
	}

	public Integer get_Protocol(){
		return c_Protocol;
	}
	public void set_Protocol(Integer protocol){
		c_Protocol = protocol;
		c_CurrentFilter = null; // Invalidate filter
		if (c_NetworkTap != null ){
			c_NetworkTap.requestBufferReset();
		}
			
	}
	public String get_Address(){
		return c_Address;
	}
	public void  set_Address(String host){
		c_Address = host;
		c_CurrentFilter = null; // Invalidate filter
	}


	public String get_Match(){
		return c_Match;
	}
	public void set_Match(String match){
		c_Match = match;
		c_CurrentFilter = null; // Invalidate filter
	}
	private Integer c_ContentLength = Integer.valueOf(0);
	public Integer get_ContentLength(){
		return c_ContentLength;
	}
	public void set_ContentLength(Integer len){
		c_ContentLength = len;
	}
	public int getContentLength(){
		return c_ContentLength.intValue();
	}
	public AnalysisDataDef def_NetworkDevice(AnalysisDataDef theDataDef){
		AFEnum devices = new AFEnum("NetworkDevices");
		if (c_NetworkDevices.size() > 0){
			for (int n= 0; n < c_NetworkDevices.size(); n++)
				devices.addEntry(n, c_NetworkDevices.get(n).getDescription());
			theDataDef.setEnum(devices);
		}
		return theDataDef;
	}

	// ANALYSIS NODE Methods
	public void _init(){
		super._init();
		new BackgroundInit(this);
	}
	public void _init_bkg(){
		c_NetworkDevices = PcapUtility.getNetworkDevices();
	}
	public void _start(){
		super._start();
		c_NetworkTap = new NetworkTap_Thread(this) ;
	}
	public void _stop(){
		super._stop();
		if (c_NetworkTap != null){
			c_NetworkTap.stop();
			c_NetworkTap = null;
		}
	}	
	public void _reset(){
		super._reset();	
		if (c_NetworkTap != null){
			c_NetworkTap.stop();
			c_NetworkTap = null;
		}
		c_NetworkTap = new NetworkTap_Thread(this) ;
	}
	@Override
	public void handlePacket(String packet) {
		publish(new AnalysisEvent(this, "PACKET",packet));
	}
	public void handlePacket(AFPacket afp) {
		publish(new AnalysisEvent(afp.getTimestamp(), this, afp.getAnalysisData()));
	}
	@Override
	public String getThreadLabel() {
		return "NetworkSource";
	}
	@Override
	public PacketFilter getPacketFilter(){
		if (c_CurrentFilter == null){		
			c_CurrentFilter = new PacketFilter();
			if (c_Protocol != null)
				c_CurrentFilter.setProtocol(c_Protocol);
			if (c_Address != null)
				c_CurrentFilter.setAddress(c_Address);
			if(c_Match != null)
				c_CurrentFilter.setMatch(c_Match);
		}
		return c_CurrentFilter;
	}
	public String getDeviceName(){
		return c_NetworkDevices.get(c_DeviceNo).getName();
	}

	
}
