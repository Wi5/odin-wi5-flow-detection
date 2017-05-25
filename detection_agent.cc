/*
 * DetectionAgent.{cc,hh}
 */


#include <click/config.h>
#include <click/router.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <click/handlercall.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include "detection_agent.hh"
#include <iostream>
#include <string>
#include <sstream>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

CLICK_DECLS

void detection_thread(Timer *timer, void *);  //only for screen report

int RESCHEDULE_INTERVAL_GENERAL_DETECTION = 10;         //time interval [sec] for periodic report by screen. General_timer will be rescheduled (to print flows, update flows) PERIODIC REPORT
uint32_t THRESHOLD_FLOWS_SENT = 4000000;      //time interval [usec] after which a detectedFlow message can be sent again to the Odin controller (e.g. THRESHOLD_FLOW_SENT = 1000000 means 1 second
int THRESHOLD_REMOVE_FLOWS = 15;              //time interval [sec] after which the old flows will be removed

DetectionAgent::DetectionAgent()
: _debug_level(0)
{
	_general_timer.assign (&detection_thread, (void *) this);
}

DetectionAgent::~DetectionAgent()
{
}

int
DetectionAgent::initialize(ErrorHandler*)
{
    _general_timer.initialize(this);
	_general_timer.schedule_now();
	return 0;
}



/*
 * Click Element method
 */
int
DetectionAgent::configure(Vector<String> &conf, ErrorHandler *errh)
{
  // read the arguments of the .cli file
  if (Args(conf, this, errh)
  .read_m("DETECTION_AGENT_IP", _detection_agent_ip)
  .read_m("DEBUG_DETECTION", _debug_level)
  .complete() < 0)
  return -1;

  return 0;
}


/**
 * This element has 1 input ports and 1 output ports.
 *
 * In-port-0: Any ethernet encapsulated frame. 
 *
 * Out-port-0: Used exclusively to talk to a Socket UDP to be used
 *             to communicate with the Odin Controller.
 */
void
DetectionAgent::push(int port, Packet *p)
{
  if (port == 0) {
    // This means that the packet is coming from the higher layer
	// Get values for FLOW

	click_ether *eh = (click_ether *) p->data();
	//fprintf(stderr, "Ether type: %d\n", eh->ether_type);
	//fprintf(stderr, "ETHERTYPE_IP: %d\n", ETHERTYPE_IP);

	if (htons(eh->ether_type) != ETHERTYPE_IP){
			p->kill();
			return;
	}
	
	click_ip *iph = (click_ip *) (p->data() + 14);

	IPAddress src_ip (iph->ip_src);
	IPAddress dst_ip (iph->ip_dst);
	uint8_t   protocol = iph->ip_p;
	uint16_t  src_port = 0;
	uint16_t  dst_port = 0;

	//fprintf(stderr,"[DetectionAgent.cc]     -> Source IP: %s\n", src_ip.unparse().c_str()); 
	//fprintf(stderr,"[DetectionAgent.cc]     -> Destination IP: %s\n", dst_ip.unparse().c_str()); 
	//fprintf(stderr,"[DetectionAgent.cc]     -> Protocol: %i\n", protocol);
 

	if (protocol == IP_PROTO_TCP) {
		click_tcp *tcph = (click_tcp *) (p->data() + 14 + 20);
		src_port = htons(tcph->th_sport);
		dst_port = htons(tcph->th_dport);
	}

	if (protocol == IP_PROTO_UDP) {

		click_udp *udph = (click_udp *) (p->data() + 14 + 20);
		src_port = htons(udph->uh_sport);
		dst_port = htons(udph->uh_dport);
	}

	// if the packet is not TCP nor UDP, end (e.g. it is ICMP)
	if ((src_port == 0) && (dst_port ==0)) {
			p->kill();
			return;
	}

	//fprintf(stderr,"[DetectionAgent.cc]     -> Source Port: %i\n", src_port); 
	//fprintf(stderr,"[DetectionAgent.cc]     -> Destination Port: %i\n", dst_port); 

	Flow flw;
	int i = 0;
	Timestamp now = Timestamp::now();
	for (Vector<DetectionAgent::Flow>::const_iterator iter = _flows_list.begin();
           iter != _flows_list.end(); iter++) {
     
		flw = *iter;
		++i;

		if ((flw.src_ip == src_ip) && (flw.dst_ip == dst_ip) &&
			(flw.src_port == src_port) && (flw.dst_port == dst_port) &&
			(flw.protocol == protocol)) {
			//fprintf(stderr,"[DetectionAgent.cc]Known flow : %i\n", i);
			_flows_list.at(i-1).last_flow_heard = now; // update the timestamp
			Timestamp age = now - flw.last_flow_sent;
			if (((age.sec() * 1000000 ) + age.usec() ) > THRESHOLD_FLOWS_SENT){
						sent_detected_flows(flw);
						_flows_list.at(i-1).last_flow_sent = now; // update the timestamp
			}
			p->kill();
			return;
		}
	}
	//fprintf(stderr,"[DetectionAgent.cc]New flow: %i\n", i);
	// Add flow
	flw.src_ip = src_ip;
	flw.dst_ip = dst_ip;
	flw.src_port = src_port;
	flw.dst_port = dst_port;
	flw.protocol = protocol;
	flw.last_flow_heard = now;
	sent_detected_flows (flw);
	flw.last_flow_sent = now;
	_flows_list.push_back (flw);
  }

  p->kill();
  return;
}


/* This function sends the identified flows to the controller. 
It is controlled by the THRESHOLD_FLOWS_SENT timer

The information of a flow is sent IF the time since its last sent is greater than THRESHOLD_FLOWS_SENT
*/
void
DetectionAgent::sent_detected_flows (Flow flw)
{

    // Send flow message to the Odin controller
    StringAccum sa;
	int protocol = 0;

	if (flw.protocol == IP_PROTO_TCP) 
		protocol = IP_PROTO_TCP;
	else if (flw.protocol == IP_PROTO_UDP) 
		protocol = IP_PROTO_UDP;
   
	sa << "detectedFlow " << flw.src_ip.unparse() << " " << flw.dst_ip.unparse() << " " << protocol << " " << flw.src_port << " " << flw.dst_port << "\n";

	//sa << "detectedFlow " << flw.src_ip.unparse() << " " << flw.dst_ip.unparse() << " " << flw.protocol << " " << flw.src_port << " " << flw.dst_port << "\n";

    String payload = sa.take_string();
    WritablePacket *odin_flow_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
    output(0).push(odin_flow_packet);
		
	//flw->last_flow_sent = now; // update the timestamp
			
	if (_debug_level % 10 > 0)
		fprintf(stderr, "[DetectionAgent.cc]   flow  message sent: %s\n", payload.c_str()); 
}


/* This debug function prints info about clients */
void
DetectionAgent::print_flows_state()
{
	Flow flw;
	if (_debug_level % 10 > 0) {    // debug is activated
		if (_debug_level / 10 == 1)		// demo mode. I print more visual information, i.e. rows of "#'
			fprintf(stderr, "##################################################################\n");

		fprintf(stderr,"[DetectionAgent.cc] ##### Periodic report. Number of flows: %i\n", _flows_list.size());
		
		if(_flows_list.size() != 0) {
			int num_flow = 0;
			for (Vector<DetectionAgent::Flow>::const_iterator iter = _flows_list.begin();
			   iter != _flows_list.end(); iter++) {
        
				flw = *iter;
				++num_flow;
				fprintf(stderr,"[DetectionAgent.cc]Flow: %i\n", num_flow);
				fprintf(stderr,"[DetectionAgent.cc]     -> Source IP: %s\n", flw.src_ip.unparse().c_str()); 
				fprintf(stderr,"[DetectionAgent.cc]     -> Destination IP: %s\n", flw.dst_ip.unparse().c_str()); 
				fprintf(stderr,"[DetectionAgent.cc]     -> Protocol: %i\n", flw.protocol); 
				fprintf(stderr,"[DetectionAgent.cc]     -> Source Port: %i\n", flw.src_port); 
				fprintf(stderr,"[DetectionAgent.cc]     -> Destination Port: %i\n", flw.dst_port); 
				fprintf(stderr,"[DetectionAgent.cc]     -> last sent: %d.%06d sec\n", flw.last_flow_sent.sec(), flw.last_flow_sent.subsec());
				fprintf(stderr,"[DetectionAgent.cc]     -> last heard: %d.%06d sec\n", flw.last_flow_heard.sec(), flw.last_flow_heard.subsec());
			}

		}			

		if (_debug_level / 10 == 1)		// demo mode. I print more visual information
				fprintf(stderr, "##################################################################\n\n");
	}
	
	// Updates the flows list. It is controlled by the THRESHOLD_REMOVE_FLOWS. 

	//int count = 0;
	Timestamp now = Timestamp::now();
	for (Vector<DetectionAgent::Flow>::iterator iter = _flows_list.begin();
		   iter != _flows_list.end(); iter++) {
        
		flw = *iter;
		
		//fprintf(stderr,"[DetectionAgent.cc]#Flow: %d\n",++count);

		
		Timestamp age = now - flw.last_flow_heard;
		//fprintf(stderr,"[DetectionAgent.cc]     -> now: %d.%06d sec\n", now.sec(), now.subsec());
		//fprintf(stderr,"[DetectionAgent.cc]     -> age: %d.%06d sec\n", age.sec(), age.subsec());
		//fprintf(stderr,"[DetectionAgent.cc]     -> last heard: %d.%06d sec\n", flw.last_flow_heard.sec(), flw.last_flow_heard.subsec());

		if (age.sec() > THRESHOLD_REMOVE_FLOWS){
			if (_debug_level % 10 > 0)
				fprintf(stderr,"\n[DetectionAgent.cc] Cleaning old flow\n");
			_flows_list.erase(iter); 
			--iter;
			//fprintf(stderr,"[DetectionAgent.cc]#Flows: %d\n", _flows_list.size());
			if (_flows_list.size() == 0)
				return;
		}
	}
}


/* Thread for general purpose (i.e. print debug info about them)*/
void detection_thread(Timer *timer, void *data){

    DetectionAgent *agent = (DetectionAgent *) data;

    agent->print_flows_state();

    timer->reschedule_after_sec(RESCHEDULE_INTERVAL_GENERAL_DETECTION);

}


/*
 * For recovery from controller
 *
 *
 * */

String
DetectionAgent::read_handler(Element *e, void *user_data)
{
  StringAccum sa;

  //sa << "\n";
  sa << "";
  return sa.take_string();
}


int
DetectionAgent::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{
  return 0;
}


void
DetectionAgent::add_handlers()
{
  add_read_handler("table", read_handler, handler_view_mapping_table);
  add_read_handler("channel", read_handler, handler_channel);
  add_read_handler("interval", read_handler, handler_interval);
  add_read_handler("rxstats", read_handler, handler_rxstat);
  add_read_handler("txstats", read_handler, handler_txstat);
  add_read_handler("subscriptions", read_handler, handler_subscriptions);
  add_read_handler("debug", read_handler, handler_debug);
  add_read_handler("report_mean", read_handler, handler_report_mean);
  add_read_handler("scan_client", read_handler, handler_scan_client);

  add_write_handler("add_vap", write_handler, handler_add_vap);
  add_write_handler("set_vap", write_handler, handler_set_vap);
  add_write_handler("remove_vap", write_handler, handler_remove_vap);
  add_write_handler("channel", write_handler, handler_channel);
  add_write_handler("interval", write_handler, handler_interval);
  add_write_handler("subscriptions", write_handler, handler_subscriptions);
  add_write_handler("debug", write_handler, handler_debug);
  add_write_handler("send_probe_response", write_handler, handler_probe_response);
  add_write_handler("testing_send_probe_request", write_handler, handler_probe_request);
  add_write_handler("handler_update_signal_strength", write_handler, handler_update_signal_strength);
  add_write_handler("signal_strength_offset", write_handler, handler_signal_strength_offset);
  add_write_handler("channel_switch_announcement", write_handler, handler_channel_switch_announcement);
  add_write_handler("scan_client", write_handler, handler_scan_client);
}




CLICK_ENDDECLS
EXPORT_ELEMENT(DetectionAgent)
ELEMENT_REQUIRES(userlevel)