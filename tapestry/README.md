# Tapestry: A Network Complexity Analyzer

## Overview

Tapestry is a system that measures network complexity by capturing Domain
Name System (DNS) endpoint interaction data via OpenFlow enabled network
taps in front of one or more of an organization's internal recursive DNS
servers.

Network interaction data is collected over time, distinct organizational
activities are detected, and a Network Complexity Index (NCI) is computed
on-line.  The NCI can be viewed and graphed in near real-time via a built
in Web based interface.

## Requirements

Tapestry requires:

* Erlang/OTP distributed computing platform, available from
    [Erlang.org](http://www.erlang.org/download.html)
* One or more servers running the Erlang to aggregate the data and 
    calculate the NCI.
* One or more internal recursive DNS servers to provide the raw data feeds
* One or more OpenFlow enabled switches or network white boxes with at
    least 3 ports to act as network taps. (or you can install LINC on
    the network white boxes)
* Network cabling and access to install the taps inline in front of
    the internal recursive DNS servers
* Network connectivity between the taps and machine or cluster running 
    the Erlang/OTP

## Installation

Download and compile the LOOM examples

```bash
% git clone https://github.com/FlowForwarding/loom
% make
```

This builds the Tapestry collector (tapestry) and configuration node
(icontrol).  To build only tapestry and icontrol, run make in the
tapestry and icontrol directories.

If required, download and compile LINC for the network switches

```bash
% git clone https://github.com/FlowForwarding/LINC-Switch.git
```

You will need to create ```$LINC_ROOT/rel/files/sys.config``` file by adding the correspond ports and adding the Tapestry
Controller.  There are 2 ports needed for Tapestry Controller and hence, we can generate a sys.config file by running the below command .
```bash
% cd $LINC_ROOT
% scripts/config_gen -s 0 eth1 eth2 eth3 eth4 -c tcp:10.10.10.75:6633 tcp:10.10.10.75:6634 -o rel/files/sys.config
% make compile
% make rel
```

## Deployment

An example deployment diagram: ![alt text][Illustration]

[Illustration]: https://raw.github.com/FlowForwarding/tapestry/master/docs/images/tapestry_deployment.jpg "Tapestry deployment"

## Running Tapestry

### First Install Flows on the Switch and make sure everything is working

Use icontrol to install the flows on the Switch

Start the icontrol node
```bash
# cd icontrol
# rel/icontrol/bin/icontrol console
```

See which switches are connected

```erlang
> iof:switches().
Switch-Key DatapathId                       IpAddr            Version
---------- -------------------------------- ----------------- -------
*1         {0,<<8,0,39,197,149,72>>}        {192,168,56,102}  4      
 2         {1,<<8,0,39,197,149,72>>}        {192,168,56,102}  4      
ok
```

Identify the switch you want to configure.  Use the Switch-Key for that
switch in the following commands.  The examples assume you want to configure
the switch with the Switch-Key of 1 (datapath id is {0,<<8,0,39,197,149,72>>}).

```erlang
> iof:tapestry_config(1, 2, 3, [{10,2,3,4},{10,2,3,44}]).
```

Removes all the flows from table 0, copies udp traffic entering port 2
to the controller from 10.2.3.4 and 10.2.3.44 (the DNS servers),
and bridges ports 2 and 3.

```erlang
> iof:flows(1).
```

Shows all the flows installed on the switch by sending the flow_stats_request
to the switch.

Now test connectivity.  If the DNS Server IP address connected to Port 1 of the LINC Switch is 10.10.10.10, then
```bash
# dig @10.10.10.10 flowforwarding.org
```

Now you can start Tapestry Collector
```erlang
# cd tapestry
# rel/tapestry/bin/tapestry start
```

Using a browser, go to URL - http://<tapestry_collector_hostname:28080/nci.html to see NCI graph and number.

### Tapestry configuration for icontrol

You can create config files for icontrol to capture the tapestry configuration.
The format of this file is:

```erlang
{switch, [{ip_addr, {192,168,56,102}},
          {dns_port, 1},
          {client_port, 2},
          {dns_ips, [{10,0,2,60}, {10,48,2,5}]}
]}.
{switch, [{dpid, {0,<<8,0,39,197,149,72>>}},
          {dns_port, 1},
          {client_port, 2},
          {dns_ips, [{10,0,2,60}, {10,48,2,5}]}
]}.
```

Switches are identified by either ip address or datapath id (dpid).  The other
fields are the port connected to the DNS server (dns_port), the port connected
to the rest of the network (client_port) and the ip addresses of the
DNS servers.  There can be any number of switch tuples in the config file.

```erlang
> iof:tapestry_config(all, Filename).
```

Configures all of the attached switches using information in Filename.

```erlang
> iof:tapestry_config(Key, Filename).
```

Configures only the switch with the switch key Key using the information
in Filename.

## Additional Documentation
>1. Technical White Paper: “[A Network Complexity Index for Networks of Networks] (http://www.flowforwarding.org/nci-article)” by Stuart Bailey and Robert L. Grossman
>2. NCI White Paper: [Tapestry for Tracking Network Complexity Index (NCI)] (http://www.infoblox.com/downloads/resources/network-complexity/download)
>3. Tapestry [Architecture Details] (https://github.com/FlowForwarding/tapestry/blob/master/docs/Tapestry.pdf?raw=true)