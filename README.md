odin-wi5-flow-detection
=======================

The objective of this tool is to integrate detection of flows within the Odin wi5 framework. The idea is to identify flows belonging to different services, and to report this to the wi5 Controller. This information will be taken into account when running the different radio resource management algorithms. For example, if a real-time flow has been detected, then the Controller should act in order to grant the delay constraints required by that service.

The detection tool is based on Click modular router. See https://github.com/kohler/click.git

General scheme of Odin and how the detector is integrated
---------------------------------------------------------

The next figure shows the general scheme. The part covered in this repository is only the **detector**:
- It receives duplicated traffic flows.
- It periodically sends the information of these flows to the Odin controller. It uses a 5-tuple to define a flow, including IP addresses, ports and protocol.

```
           Internet
             ^
             |in & out traffic
             v
        +----------+       in & out         +----------+
        | router & | ----- duplicated ----> | odin     |
        |classifier|       traffic          | detector |
        +----------+       of interest      +----------+
             ^                                |
             |                                | real-time flows' info
             |in & out traffic                v
      data   |                        +---------------+
      plane  |                        |odin controller|
             |                        +---------------+
             |                          ^
             |                          | control plane
             v                          v

 |    |      |    |                |    |
+------+    +------+              +------+    
|  AP  |    |  AP  |     ...      |  AP  |
+------+    +------+              +------+

    |
 +---+
 |STA|
 |   |
 +---+
```

Scheme of the detector
----------------------

Every packet that enters to the detector interface will be analyzed and, if necessary, information about the flow will be sent to the Odin controller.

So you first have to duplicate and classify your traffic with another tool. You can do this with e.g. iptables, duplicating the traffic and sending it to the interface used by Click.

```
                  +-----------------------------+
                  |                             |
  in & out       +------+   +-----------------+ |               +----------+
--duplicated---->| ethX |-->| click with      | |--odinsocket-->| odin     |
  traffic        +------+   | odin detection  | |      UDP      |controller|
  of interest     |         +-----------------+ |   port 2819   +----------+
                  |          detector           |
                  +-----------------------------+
                 
               |                                   |
               |     we are covering this part     |
               |<--------------------------------->|
```

Compile the detector
--------------------

- Download Click modular router (`git clone https://github.com/kohler/click.git`)

- Copy the two files `detection_agent.cc` and `detection_agent.hh` to `click/elements/local`

- Compile Click with these options
    `~click$ ./configure --prefix=/home/proyecto --enable-local --enable-userlevel`

- Build the element list
    `~click$ make elemlist`

- Run `~click$ make`

You will then have a Click in `click/userlevel/click` including the detection agent.


Run the detector
----------------

Create the `.click` file with the Python script. One example:

    ~$ python detection_agent-click-file-gen.py 192.168.T.Z 2819 192.168.X.Y 2 12 > ../detection.cli

And run Click

    ~$ ./click/userlevel/click detection.cli

Duplicate the traffic to be analyzed and direct it to the network interface of the detection machine
----------------------------------------------------------------------------------------------------

You can use the `-j TEE` option of `iptables` to duplicate the traffic. This is an example that works in a kernel 3, but not in a kernel 2.6:

    ~$ iptables -t mangle -A PREROUTING -s 192.168.200.3 -j TEE --gateway 192.168.0.4

Information caputred by the detection agent
-------------------------------------------

This is the payload of the messages sent from the agent to the wi-5 controller. It includes the word 'Flow', plus a 5-tuple with the IP addresses, the protocol field and the source and destination ports:

```
Flow 192.168.101.2 192.168.101.3 . 37699 3000
Flow 192.168.101.2 192.168.101.3 . 44170 3000
Flow 192.168.101.2 192.168.101.3 . 52483 3000
Flow 192.168.101.2 192.168.101.3 . 37699 3000
Flow 192.168.101.2 192.168.101.3 . 36399 3000
```
**Note**. In this case, the value of the `protocol` field cannot be observed, and it is shown as a dot. The cause is that it corresponds to UDP, number 17 decimal and 11 hexadecimal, which has no representation in ASCII.


Real-time information is shown by the screen every time a new flow message is sent to the wi-5 controller:

```
[DetectionAgent.cc]   flow  message sent: Flow 192.168.101.2 192.168.101.3  49001 3000
[DetectionAgent.cc]   flow  message sent: Flow 192.168.101.2 192.168.101.3  39199 3000
[DetectionAgent.cc]   flow  message sent: Flow 192.168.101.2 192.168.101.3  49001 3000
```

Periodic reports are also generated by the screen for debugging purposes. This is an example of a periodic report including the information of 4 different flows:

```
##################################################################
[DetectionAgent.cc] ##### Periodic report. Number of flows: 4
[DetectionAgent.cc]Flow: 1
[DetectionAgent.cc]     -> Source IP: 192.168.101.2
[DetectionAgent.cc]     -> Destination IP: 192.168.101.3
[DetectionAgent.cc]     -> Protocol: 17
[DetectionAgent.cc]     -> Source Port: 55992
[DetectionAgent.cc]     -> Destination Port: 3000
[DetectionAgent.cc]     -> last sent: 1479224716.755008897 sec
[DetectionAgent.cc]     -> last heard: 1479224707.696236085 sec
[DetectionAgent.cc]Flow: 2
[DetectionAgent.cc]     -> Source IP: 192.168.101.2
[DetectionAgent.cc]     -> Destination IP: 192.168.101.3
[DetectionAgent.cc]     -> Protocol: 17
[DetectionAgent.cc]     -> Source Port: 51794
[DetectionAgent.cc]     -> Destination Port: 3000
[DetectionAgent.cc]     -> last sent: 1479224716.195016870 sec
[DetectionAgent.cc]     -> last heard: 1479224710.160633586 sec
[DetectionAgent.cc]Flow: 3
[DetectionAgent.cc]     -> Source IP: 192.168.101.2
[DetectionAgent.cc]     -> Destination IP: 192.168.101.3
[DetectionAgent.cc]     -> Protocol: 17
[DetectionAgent.cc]     -> Source Port: 41530
[DetectionAgent.cc]     -> Destination Port: 3000
[DetectionAgent.cc]     -> last sent: 1479224716.675013732 sec
[DetectionAgent.cc]     -> last heard: 1479224712.656139175 sec
[DetectionAgent.cc]Flow: 4
[DetectionAgent.cc]     -> Source IP: 192.168.101.2
[DetectionAgent.cc]     -> Destination IP: 192.168.101.3
[DetectionAgent.cc]     -> Protocol: 17
[DetectionAgent.cc]     -> Source Port: 41333
[DetectionAgent.cc]     -> Destination Port: 3000
[DetectionAgent.cc]     -> last sent: 1479224716.365020750 sec
[DetectionAgent.cc]     -> last heard: 1479224715.360148596 sec
##################################################################
```

Information shown in the wi-5 odin controller
---------------------------------------------

This is the log information you will see in the controller:
```
17:24:55.899 [pool-3-thread-8] INFO  n.f.odin.master.OdinMaster - We receive a detected flow 192.168.2.130 192.168.2.131 17 58463 32000 registered as Id: 1  from: 192.168.1.200
17:24:55.899 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager] Detected flow
17:24:55.899 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Source IP: 192.168.2.130
17:24:55.899 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Destination IP: 192.168.2.131
17:24:55.899 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Protocol IP: 17
17:24:55.899 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Source Port: 58463
17:24:55.900 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Destination Port: 32000
17:24:55.900 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager] from agent: /192.168.1.200 at 1497367495900
17:24:55.900 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - 
17:24:55.900 [pool-3-thread-8] INFO  n.f.o.a.FlowDetectionManager - 

17:24:56.200 [pool-3-thread-10] INFO  n.f.odin.master.OdinMaster - We receive a detected flow 192.168.2.130 192.168.2.131 17 51408 32000 registered as Id: 1  from: 192.168.1.200
17:24:56.200 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager] Detected flow
17:24:56.200 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Source IP: 192.168.2.130
17:24:56.200 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Destination IP: 192.168.2.131
17:24:56.200 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Protocol IP: 17
17:24:56.200 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Source Port: 51408
17:24:56.200 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager]     -> Destination Port: 32000
17:24:56.201 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - [FlowDetectionManager] from agent: /192.168.1.200 at 1497367496201
17:24:56.201 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - 
17:24:56.201 [pool-3-thread-10] INFO  n.f.o.a.FlowDetectionManager - 
```
