# odin-wi5-flow-detection

The objective of this tool is to integrate detection of flows within the Odin framework. The idea is to identify flows belonging to different services, and to report this to the Odin controller. This information will be taken into account when running the different radio resource management algorithms. For example, if a real-time flow has been detected, then the Controller should act in order to grant the delay constraints required by that service.

The detection tool is based on Click modular router. See https://github.com/kohler/click.git

General scheme of Odin and how the detector is integrated
=========================================================

The next figure shows the general scheme. The part covered in this repository is only the **detector**:
- It receives duplicated traffic flows.
- It periodically sends the information of these flows to the Odin controller. It uses a 5-tuple to define a flow, including IP addresses, ports and protocol.

```
           Internet
             ^
             |in & out traffic
             v
         +-------+    in & out     +----------+
         |router | ---duplicated-->| detector |
         +-------+    traffic      +----------+
             ^        of interest      ^
             |                         |real-time flows' info
             |in & out traffic         v
      data   |                     +---------------+
      plane  |                     |odin controller|
             |                     +---------------+
             |                      ^
             |                      | control plane
             v                      v

 |    |      |    |             |    |
+------+    +------+           +------+    
|  AP  |    |  AP  |     ...   |  AP  |
+------+    +------+           +------+

    |
 +---+
 |STA|
 |   |
 +---+
```

Scheme of the detector
======================
Every packet that enters to the tap interface will be analyzed and, if necessary, information about the flow will be sent to the Odin controller.

So you first have to duplicate and classify your traffic with another tool. You can do this with e.g. iptables, duplicating the traffic and sending it to the tap interface created by Click, called `ap`.

To duplicate traffic in the router, you can use the option `iptables -tee` see e.g. http://superuser.com/questions/853077/iptables-duplicate-traffic-to-another-ip)

```
  in & out       +-----+   +-----------------+             +----------+
--duplicated---->| tap |-->|click with       |-odinsocket->| odin     |
  traffic        +-----+   |odin detection   |    UDP      |controller|
  of interest              +-----------------+             +----------+
            
               | 
               | we are covering this part
               |------------->
```

Steps to compile and run this
=============================

- Download Click modular router (`git clone https://github.com/kohler/click.git`)
- Copy the two files `detection_agent.cc` and `detection_agent.hh` to `click/elements/local`
- Compile Click with these options
    `$ ./configure --prefix=/home/proyecto --enable-local --enable-userlevel`

- Build the element list
    `$ make elemlist`

- Run `$ make`

You will then have a Click in `click/userlevel/click` including the detection agent.

You may have to be root to run Click, as it creates a tap device.
- To add some functionality in the Controller to read the information

