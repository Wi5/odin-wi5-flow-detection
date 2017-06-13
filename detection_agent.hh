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
Acts as an agent for the Odin controller. Its function is reporting about detected services

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
  void add_handlers();
  void push(int, Packet *);


  // Recovery from controller
  static String read_handler(Element *e, void *user_data);
  static int write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh);
  enum {
    handler_view_mapping_table,
    handler_num_slots,
    handler_add_vap,
    handler_set_vap,
	handler_txstat,
    handler_rxstat,
    handler_remove_vap,
    handler_channel,
    handler_interval,
    handler_subscriptions,
    handler_debug,
    handler_probe_response,
    handler_probe_request,
    handler_report_mean,
    handler_update_signal_strength,
    handler_signal_strength_offset,
    handler_channel_switch_announcement,
	handler_scan_client,
  };

  // Classes and Methods to handle flows
  class Flow {
    public:
        IPAddress src_ip;
        IPAddress dst_ip;
		uint8_t protocol;
		uint16_t src_port;
		uint16_t dst_port;  
		Timestamp last_flow_heard; // Stores the timestamp when a single flow has been heard
		Timestamp last_flow_sent; // Stores the timestamp when the last FLOW message has been sent for a single flow
  };

  Vector<Flow> _flows_list;

  //debug
  void print_flows_state();
  void sent_detected_flows (Flow flw);

  int _debug_level;		//"0" no info displayed; "1" only basic info displayed; "2" all the info displayed; "1x" demo info displayed

private:
  IPAddress _detection_agent_ip;
  Timer _general_timer;
};



CLICK_ENDDECLS
#endif