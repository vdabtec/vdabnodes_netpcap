# VDAB NetPcap Node
### Overview
This node demonstrates using pcap to monitor the network traffic. 
This should be considered only a prototype and the install package only works on windows.

| | |
|  --- |  :---: |
| Application Page    |  NA |
| Demo Web Link   | NA |

### Features
<ul>
<li>Monitors network data selected by type.
<li>Allows selection of specific source and destination Ips.
<li>Specific ports can be selected.
</ul>

### Loading the the Package
The current or standard version can be loaded directly using the VDAB Android Client following the directions
for [Adding Packages](https://vdabtec.com/vdab/docs/VDABGUIDE_AddingPackages.pdf) 
and selecting the <i>NetPcapNodes</i> package.
 
A custom version can be built using Gradle following the direction below.

* Clone or Download this project from Github.
* Open a command windows from the <i>NetPcapNodes</i> directory.
* Build using Gradle: <pre>      gradle vdabPackage</pre>

This builds a package zip file which contains the components that need to be deployed. These can be deployed by 
manually unzipping these files as detailed in the [Server Updates](https://vdabtec.com/vdab/docs/VDABGUIDE_ServerUpdates.pdf) 
 documentation.

### Known Issues as of 24 Oct  2018

* The install package is only available on windows.
* This is a PROTOTYPE and does not support monitoring all network data.
* This requires the prior installation of WINPCAP.


