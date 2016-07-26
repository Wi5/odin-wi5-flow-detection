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

void misc_thread(Timer *timer, void *);
void sent_flows(Timer *timer, void *);

int RESCHEDULE_INTERVAL_GENERAL = 30; //time interval [sec] after which general_timer will be rescheduled (to print flows)
int RESCHEDULE_INTERVAL_FLOWS = 10; //time interval [msec] after which flows_timer will be rescheduled ( e.g. RESCHEDULE_INTERVAL_FLOWS = 10 means 0.01seconds)
uint32_t THRESHOLD_FLOWS_SENT = 100000; //time interval [usec] after which a FLOW message can be sent again. e.g. THRESHOLD_FLOW_SENT = 100000 means 0.1seconds
int THRESHOLD_REMOVE_FLOWS = 10; //timer interval [sec] after which the old flows will be removed

DetectionAgent::DetectionAgent()
: _debug_level(0)
{
	_general_timer.assign (&misc_thread, (void *) this);
	_flows_timer.assign (&sent_flows, (void *) this);
}

DetectionAgent::~DetectionAgent()
{
}

int
DetectionAgent::initialize(ErrorHandler*)
{
    _general_timer.initialize(this);
	_general_timer.schedule_now();
    _flows_timer.initialize(this);
	_flows_timer.schedule_now();
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
  * In-port-0: Any ethernet encapsulated frame. Expected
 *            to be coming from a tap device
 *
 * Out-port-0: Used exclusively to talk to a Socket UDP to be used
 *             to communicate with the OdinMaster.
 */
void
DetectionAgent::push(int port, Packet *p)
{
  if (port == 0) {
    // This means that the packet is coming from the higher layer
	// Get values for FLOW
    
	click_ether *eh = (click_ether *) p->data();
	if (eh->ether_type != ETHERTYPE_IP){
			p->kill();
			return;
	}
	
	click_ip *iph = (click_ip *) (p->data() + 14);

	IPAddress src_ip (iph->ip_src);
	IPAddress dst_ip (iph->ip_dst);
	uint8_t   protocol = iph->ip_p;
	uint16_t  src_port;
	uint16_t  dst_port;

	if (protocol == IP_PROTO_TCP) {
		click_tcp *tcph = (click_tcp *) (p->data() + 20);
		src_port = tcph->th_sport;
		dst_port = tcph->th_dport;
	}

	if (protocol == IP_PROTO_UDP) {

		click_udp *udph = (click_udp *) (p->data() + 20);
		src_port = udph->uh_sport;
		dst_port = udph->uh_dport;
	}

	Flow flw;
	int i = 0;
	for (Vector<DetectionAgent::Flow>::const_iterator iter = _flows_list.begin();
           iter != _flows_list.end(); iter++) {
     
		flw = *iter;
		++i;

		if ((flw.src_ip == src_ip) && (flw.dst_ip == dst_ip) &&
			(flw.src_port == src_port) && (flw.dst_port == dst_port) &&
			(flw.protocol == protocol)) {
	
			_flows_list.at(i-1).last_flow_heard = Timestamp::now(); // update the timestamp
			p->kill();
			return;
		}
	}
	// Add flow
	flw.src_ip = src_ip;
	flw.dst_ip = dst_ip;
	flw.src_port = src_port;
	flw.dst_port = dst_port;
	flw.protocol = protocol;
	flw.last_flow_heard = Timestamp::now();
	flw.last_flow_sent = Timestamp::now();
	_flows_list.push_back (flw);
  }

  p->kill();
  return;
}





/* This function sent the identified flows to the controller. It is controlled by THRESHOLD_FLOWS_SENT timer */
void
sent_flows (Timer *timer, void *data)
{

    DetectionAgent *agent = (DetectionAgent *) data;
    
	int i = 0;

	for (Vector<DetectionAgent::Flow>::iterator iter = agent->_flows_list.begin();
           iter != agent->_flows_list.end(); iter++) {
        
		DetectionAgent::Flow flw = *iter;
		Timestamp now = Timestamp::now();
        Timestamp age = now - flw.last_flow_heard;
		++i;

		if (age.sec() > THRESHOLD_REMOVE_FLOWS){
            agent->_flows_list.erase(iter); 
	    	if (agent->_debug_level % 10 > 0)
					fprintf(stderr,"\n[DetectionAgent.cc] Cleaning old flow\n");
			continue;
        }
		age = now - flw.last_flow_sent;

		if (((age.sec() * 1000000 ) + age.usec() ) > THRESHOLD_FLOWS_SENT){

            // Send flow message to the master
            StringAccum sa;
            sa << "Flow " << flw.src_ip.unparse() << " " << flw.dst_ip.unparse() << " " << flw.protocol << " " << flw.src_port << " " << flw.dst_port << "\n";

            String payload = sa.take_string();
            WritablePacket *odin_flow_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
            agent->output(0).push(odin_flow_packet);
			
			agent->_flows_list.at(i-1).last_flow_sent = now; // update the timestamp
			
			if (agent->_debug_level % 10 > 1)
				fprintf(stderr, "[DetectionAgent.cc]   flow  messaage sent: %s\n", payload.c_str()); 
        }
	}
	
    timer->reschedule_after_msec(RESCHEDULE_INTERVAL_FLOWS);  
}


/* This debug function prints info about clients */
void
DetectionAgent::print_flows_state()
{
	if (_debug_level % 10 > 0) {    // debug is activated
		if (_debug_level / 10 == 1)		// demo mode. I print more visual information, i.e. rows of "#'
			fprintf(stderr, "##################################################################\n");

		fprintf(stderr,"[DetectionAgent.cc] ##### Periodic report. Number of flows: %i\n", _flows_list.size());
		
		if(_flows_list.size() != 0) {
			int num_flow = 0;
			for (Vector<DetectionAgent::Flow>::const_iterator iter = _flows_list.begin();
			   iter != _flows_list.end(); iter++) {
        
				Flow flw = *iter;
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
}


/* Thread for general purpose (i.e. print debug info about them)*/
void misc_thread(Timer *timer, void *data){

    DetectionAgent *agent = (DetectionAgent *) data;

    agent->print_flows_state();

    timer->reschedule_after_sec(RESCHEDULE_INTERVAL_GENERAL);

}


CLICK_ENDDECLS
EXPORT_ELEMENT(DetectionAgent)
ELEMENT_REQUIRES(userlevel)