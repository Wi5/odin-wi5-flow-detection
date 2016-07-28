/*
 * DetectionAgent.{cc,hh}
 */


#ifndef CLICK_DETECTIONAGENT_HH
#define CLICK_DETECTIONAGENT_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashtable.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

/*
=c
DetectionAgent

=s basictransfer
No ports

=d
Acts as an agent for the Odin controller. Its function is to report detected flows (services), 
identified by 5-tuples (IP addresses, ports and protocol)

=a
Whatever
*/

class DetectionAgent : public Element {
public:
  DetectionAgent();
  ~DetectionAgent();

  // From Click
  const char *class_name() const	{ return "DetectionAgent"; }
  const char *port_count() const  { return "1/1"; }
  const char *processing() const  { return PUSH; }
  int initialize(ErrorHandler *); // initialize element
  int configure(Vector<String> &, ErrorHandler *);
  void push(int, Packet *);

  
  // Classes and Methods to handle flows
  // We use a 5-tuple to define a flow, including IP addresses, ports and protocol.
  class Flow {
    public:
        IPAddress src_ip;
        IPAddress dst_ip;
	uint8_t protocol;
	uint16_t src_port;
	uint16_t dst_port;  
	Timestamp last_flow_heard;	// Stores the timestamp when a single flow has been heard
	Timestamp last_flow_sent;	// Stores the timestamp when the last FLOW message has been sent for a single flow
  };

  Vector<Flow> _flows_list;

  //debug
  void print_flows_state();

  int _debug_level;	//"0" no info displayed; "1" only basic info displayed; "2" all the info displayed; "1x" demo info displayed

private:
  IPAddress _detection_agent_ip;
  Timer _general_timer;
  Timer _flows_timer;
};


CLICK_ENDDECLS
#endif
