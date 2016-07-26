# odin-wi5-flow-detection
Detection of flows belonging to different services

This detection is based on Click modular router. See https://github.com/kohler/click.git

Steps to run this:

- Download Click modular router (`git clone https://github.com/kohler/click.git`)
- Copy the two files `detection_agent.cc` and `detection_agent.hh` to `click/elements/local`
- Compile Click with these options
    `$ ./configure --prefix=/home/proyecto --enable-local --enable-userlevel`

- Build the element list
    `$ make elemlist`
- Run `$ make`

You will then have a Click in `click/userlevel/click` including the detection agent.

You may have to be root to run Click, as it creates a tap device.

General scheme
==============
```
           Internet
             ^
             |in & out traffic
             v
         +-------+    in & out     +----------+
         |router | ---duplicated-->| detector |
         +-------+    traffic      +----------+
             ^                         ^
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
Every packet that enters to the tap interface will be analyzed and sent to the Odin controller.

So you first have to classify your traffic with another tool.

```
  in & out     +------+            +-----+   +-----------------+             +----------+
--duplicated-->| ipfw |-real-time->| tap |-->|click with       |-odinsocket->| odin     |
  traffic      +------+          | +-----+   |odinagent_diffuse|    UDP      |controller|
                   |             |           +-----------------+             +----------+
                   | no real-time|
                   v             |
                  null           | we are covering this part
                                 |------------->
```

Things you need
===============

- To duplicate traffic in the router
    use the option `iptables -tee` see e.g. http://superuser.com/questions/853077/iptables-duplicate-traffic-to-another-ip)

- To create a tun in the detector

- To set ipfw rules to send the rt traffic to the tun  - EASY

- To set Click in the detector

- To make a .cli file in the detector

- To add a message in the .cc file of the odinagent_diffuse to send a publish-diffuse

- To add some functionality in the Controller to read the information

