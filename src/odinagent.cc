/*
 * OdinAgent.{cc,hh} -- An agent for the Odin system
 * Lalith Suresh <suresh.lalith@gmail.com>
 *
 * Copyright (c) 2012 Lalith Suresh
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <clicknet/wifi.h>
#include <click/router.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <click/handlercall.hh>
#include <clicknet/ether.h>
#include <clicknet/llc.h>
#include "odinagent.hh"
#include <iostream>
#include <string>
#include <sstream>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include <click/etheraddress.hh> // stats to file
#include <sys/stat.h>
#include <fstream>

CLICK_DECLS


void misc_thread(Timer *timer, void *);
void cleanup_lvap(Timer *timer, void *);

int RESCHEDULE_INTERVAL_GENERAL = 35; //time interval [sec] after which general_timer will be rescheduled
int RESCHEDULE_INTERVAL_STATS = 30; //time interval [sec] after which general_timer will be rescheduled
int THRESHOLD_REMOVE_LVAP = 30; //time interval [sec] after which an lvap will be removed if we didn't hear from the client
uint32_t THRESHOLD_PUBLISH_SENT = 1000000; //time interval [usec] after which a publish message can be sent again. e.g. THRESHOLD_PUBLISH_SENT = 100000 means 0.1seconds FIXME add to .cli

void scanning_thread(Timer *timer, void *);

//int RESCHEDULE_INTERVAL_SCANNING = 50; //time interval [msec] after which scanning timer will be rescheduled
//int RESCHEDULE_INTERVAL_measurement_BEACON; // time interval [msec] after which measurement beacon timer will be rescheduled. 
                                                                          // It is measurement beacon interval. 



OdinAgent::OdinAgent()
: _mean(0),
  _num_mean(0),
  _m2(0),
  _signal_offset(0),
  //_debug(true), //false
  _debug_level(0),
  _rtable(0),
  _associd(0),
  _beacon_timer(this),
  _debugfs_string(""),
  _ssid_agent_string(""),
  _tx_rate(0),
  _tx_power(0),
  _hidden(0),
  _multichannel_agents(1),
  _interval_ms_default(10),             // Inter-Beacon Interval for normal mode
  _interval_ms_burst(10),               // Inter-Beacon Interval for burst mode
  _interval_ms_measurement_beacon(100),
  _capture_mode(0),                     // Capture mode, radiotap statictics will be stored in file
  _capture_mac_str(""),                 // Mac to capture
  _burst_after_addlvap(5)               // Number of beacons to send after add_lvap or change channel
{
  _clean_stats_timer.assign(&cleanup_lvap, (void *) this);
  _general_timer.assign (&misc_thread, (void *) this);
  _scanning_timer.assign (&scanning_thread, (void *) this);
}

OdinAgent::~OdinAgent()
{
}

int
OdinAgent::initialize(ErrorHandler*)
{
  _beacon_timer.initialize(this);
  _general_timer.initialize(this);
  _general_timer.schedule_now();
  _clean_stats_timer.initialize(this);
  _clean_stats_timer.schedule_now();
  _scanning_timer.initialize(this);
  _scanning_timer.schedule_now();
  compute_bssid_mask ();
  return 0;
}

/*
 * This timer drives the beacon generation
 */
void
OdinAgent::run_timer (Timer*)
{
  for (HashTable<EtherAddress, OdinStationState>::iterator it
      = _sta_mapping_table.begin(); it.live(); it++)
  {
    // Note that the beacon is directed at the unicast address of the
    // client corresponding to the LVAP. This should
    // prevent clients from seeing each others LVAPs

    for (int i = 0; i < it.value()._vap_ssids.size (); i++) {
      send_beacon (it.key(), it.value()._vap_bssid, it.value()._vap_ssids[i], false);
    }
  }

  _beacon_timer.reschedule_after_msec(_interval_ms);
}


/*
 * Click Element method
 */
int
OdinAgent::configure(Vector<String> &conf, ErrorHandler *errh)
{
  // Default values
  _channel = 6;
  _scan_channel = 0; // Initialized in 0, so it will change the channel the first time
  _new_channel = 1;

  _csa = false; //
  _count_csa_beacon_default = 4; // Number of beacons, with CSA element, sent by the AP before channel switch
  _count_csa_beacon = _count_csa_beacon_default;

  _active_client_scanning = 0;
  _scanned_sta_mac = EtherAddress();
  _client_scanning_result = 0;
  _client_scanned_packets = 0;

  _active_AP_scanning = 0; 
  _scanning_SSID = "";
  //_AP_scanning_interval = 0;
  //_num_intervals_for_AP_scanning = 0;

  _active_measurement_beacon = 0;
  _measurement_beacon_SSID = ""; 
  //_measurement_beacon_interval = 0;
  //_num_measurement_beacon = 0;
  //_num_intervals_for_measurement_beacon = 1;
  
  // read the arguments of the .cli file
  if (Args(conf, this, errh)
  .read_mp("HWADDR", _hw_mac_addr)
  .read_m("RT", ElementCastArg("AvailableRates"), _rtable)
  .read_m("CHANNEL", _channel)
  .read_m("DEFAULT_GW", _default_gw_addr)
  .read_m("DEBUGFS", _debugfs_string)
  .read_m("SSIDAGENT", _ssid_agent_string)
  .read_m("DEBUG_ODIN", _debug_level)
  .read_m("TX_RATE", _tx_rate)    // as we are not yet able to do per-packet TPC, we use a fixed transmission rate, and we must read it to perform the calculations of the statistics
  .read_m("TX_POWER", _tx_power)  // as we are not yet able to do per-packet TPC, we use a fixed transmission power, and we must read it to perform the calculations of the statistics
  .read_m("HIDDEN", _hidden)
  .read_m("MULTICHANNEL_AGENTS", _multichannel_agents)
  .read_m("DEFAULT_BEACON_INTERVAL", _interval_ms_default)
  .read_m("BURST_BEACON_INTERVAL", _interval_ms_burst)
  .read_m("MEASUREMENT_BEACON_INTERVAL", _interval_ms_measurement_beacon)
  .read_m("CAPTURE_MODE",_capture_mode)
  .read_m("MAC_CAPTURE",_capture_mac)
  .read_m("BURST",_burst_after_addlvap)
  .complete() < 0)
  return -1;
  
  _capture_mac_str = _capture_mac.unparse_colon().c_str();

  // Put the correct value in the variable after reading
  _interval_ms = _interval_ms_default;

  return 0;
}


/*
 * This re-computes the BSSID mask for this node
 * using all the BSSIDs of the VAPs, and sets the
 * hardware register accordingly.
 */
void
OdinAgent::compute_bssid_mask()
{
  uint8_t bssid_mask[6];
  int i;

  // Start with a mask of ff:ff:ff:ff:ff:ff
  for (i = 0; i < 6; i++)
  {
    bssid_mask[i] = 0xff;
  }

  // For each VAP, update the bssid mask to include
  // the common bits of all VAPs.
  for (HashTable<EtherAddress, OdinStationState>::iterator it
      = _sta_mapping_table.begin(); it.live(); it++)
  {
    for (i = 0; i < 6; i++)
    {
      const uint8_t *hw= (const uint8_t *)_hw_mac_addr.data();
      const uint8_t *bssid= (const uint8_t *)it.value()._vap_bssid.data();
      bssid_mask[i] &= ~(hw[i] ^ bssid[i]);
    }
  }

  // Update bssid mask register through debugfs
  FILE *debugfs_file = fopen (_debugfs_string.c_str(),"w");



  if (debugfs_file!=NULL)
  {
    if (_debug_level % 10 > 1)
      fprintf(stderr, "[Odinagent.cc] bssid mask: %s\n", EtherAddress (bssid_mask).unparse_colon().c_str());
    fprintf(debugfs_file, "%s\n", EtherAddress (bssid_mask).unparse_colon().c_str());//, sa.take_string().c_str());
    fclose (debugfs_file);
  }
}

/**
 * Invoking this implies adding a client
 * to the VAP.
 *
 * return -1 if the STA is already assigned
 */
int
OdinAgent::add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssids)
{
  // First make sure that this VAP isn't here already, in which
  // case we'll just ignore the request
  if (_sta_mapping_table.find(sta_mac) != _sta_mapping_table.end())
  {
    if (_debug_level % 10 > 0)
    fprintf(stderr, "[Odinagent.cc] Ignoring VAP add request because it has already been assigned a slot\n");
    return -1;
  }

  if (_debug_level % 10 > 0) {
    //fprintf(stderr, "[Odinagent.cc] add_lvap %s\n", sta_mac.unparse_colon().c_str());
    if (_debug_level / 10 == 1)    // demo mode. I print more visual information
      fprintf(stderr, "##################################################################\n");

    fprintf(stderr, "[Odinagent.cc] add_lvap (%s, %s, %s, %s)\n", sta_mac.unparse_colon().c_str()
                                              , sta_ip.unparse().c_str()
                                              , sta_bssid.unparse().c_str()
                                              , vap_ssids[0].c_str());
    if (_debug_level / 10 == 1)    // demo mode. I print more visual information
      fprintf(stderr, "##################################################################\n\n");
  }

  OdinStationState state;
  state._vap_bssid = sta_bssid;
  state._sta_ip_addr_v4 = sta_ip;
  state._vap_ssids = vap_ssids;
  _sta_mapping_table.set(sta_mac, state);

  // We need to prime the ARP responders
  Router *r = router();

  if (_debug_level % 10 > 1)
    if ( r->find("fh_arpr" ) == NULL )
      fprintf(stderr, "[Odinagent.cc] addLVAP: fh_arpr element not found\n");

  // ARP response to the ARP requests from device (coming from the wired network)
  int result = HandlerCall::call_write (r->find("fh_arpr"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());
  if (_debug_level % 10 > 1)
    fprintf(stderr,"[Odinagent.cc] addLVAP: result of the fh_arpr call write: %i\n", result);

  if (_debug_level % 10 > 1)
    if ( r->find("arp_resp" ) == NULL )
      fprintf(stderr, "[Odinagent.cc] addLVAP: arp_resp element not found\n");

  // ARP response to the ARP requests from the wireless network
  result = HandlerCall::call_write (r->find("arp_resp"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());
  if (_debug_level % 10 > 1)
    fprintf(stderr,"[Odinagent.cc] addLVAP: result of the arp_resp call write: %i\n", result);

  compute_bssid_mask();

  // Start beacon generation
  if (_sta_mapping_table.size() == 1) {
      _beacon_timer.schedule_now();
  }

  // In case this invocation is in response to a page-faulted-probe-request,
  // then process the faulty packet
  HashTable<EtherAddress, String>::const_iterator it = _packet_buffer.find(sta_mac);
  if (it != _packet_buffer.end()) {
    OdinStationState oss = _sta_mapping_table.get (sta_mac);

    _interval_ms = _interval_ms_burst;               // Decreasing interval for improving the handoff
    _beacon_timer.schedule_after_msec(_interval_ms);

    //sleep(50);
    //sleep(50);
    for (int j = 1; j <= _burst_after_addlvap; j++) { // Send beacons, help in the case of a channel switch
        
      if (it.value() == "") {
        for (int i = 0; i < oss._vap_ssids.size(); i++) {
          send_beacon(sta_mac, oss._vap_bssid, oss._vap_ssids[i], true);
          if (_debug_level % 10 > 1)
            fprintf(stderr, "[Odinagent.cc] Send beacons (active scanning with broadcast ssid): %i\n",j);
        }
      }
      else {
        for (int i = 0; i < oss._vap_ssids.size(); i++) {
          if (oss._vap_ssids[i] == it.value()) {
              send_beacon(sta_mac, oss._vap_bssid, it.value(), true);
              if (_debug_level % 10 > 1)
                fprintf(stderr, "[Odinagent.cc] Send beacons (active scanning with unicast ssid): %i\n",j);
              break;
          }
        }
      }
    }
    _packet_buffer.erase(it.key());
    _interval_ms = _interval_ms_default;  //Increasing beacon interval again to default value
    _beacon_timer.schedule_after_msec(_interval_ms);
  }

  if (_debug_level % 10 > 0)
    fprintf(stderr, "[Odinagent.cc] Lvap added\n");

  return 0;
}


/**
 * Invoking this implies updating a client's
 * details. To be used primarily to update
 * a client's IP address
 *
 * return -1 if the STA is already assigned
 */
int
OdinAgent::set_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssids)
{
  if (_debug_level % 10 > 0) {
    if (_debug_level / 10 == 1)    // demo mode. I print more visual information
      fprintf(stderr, "##################################################################\n");
    fprintf(stderr, "[Odinagent.cc] set_lvap (%s, %s, %s, %s)\n", sta_mac.unparse_colon().c_str()
                                                , sta_ip.unparse().c_str()
                                                , sta_bssid.unparse().c_str()
                                                , vap_ssids[0].c_str());
    if (_debug_level / 10 == 1)    // demo mode. I print more visual information
      fprintf(stderr, "##################################################################\n\n");
  }

  // First make sure that this VAP isn't here already, in which
  // case we'll just ignore the request
  if (_sta_mapping_table.find(sta_mac) == _sta_mapping_table.end())
  {
    if (_debug_level % 10 > 0)
      fprintf(stderr, "[Odinagent.cc] Ignoring LVAP set request because the agent is not hosting the LVAP\n");
    return -1;
  }

  OdinStationState state;
  state._vap_bssid = sta_bssid;
  state._sta_ip_addr_v4 = sta_ip;
  state._vap_ssids = vap_ssids;
  _sta_mapping_table.set(sta_mac, state);

  // We need to update the ARP responder
  Router *r = router();

  if (_debug_level % 10 > 1)
    if ( r->find("fh_arpr" ) == NULL )
      fprintf(stderr, "[Odinagent.cc] setLVAP: fh_arpr element not found\n");

  // ARP response to the ARP requests from device (coming from the wired network)
  int result = HandlerCall::call_write (r->find("fh_arpr"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());
  //fprintf(stderr,"[Odinagent.cc] setLVAP: result of the fh_arpr call write: %i\n", result);

  if (_debug_level % 10 > 1)
    if ( r->find("arp_resp" ) == NULL )
      fprintf(stderr, "[Odinagent.cc] setLVAP: arp_resp element not found\n");

  // ARP response to the ARP requests from the wireless network
  result = HandlerCall::call_write (r->find("arp_resp"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());

  if (_debug_level % 10 > 1)
    fprintf(stderr,"[Odinagent.cc] setLVAP: result of the arp_resp call write: %i\n", result);

  compute_bssid_mask();

  if (_debug_level % 10 > 0)
    fprintf(stderr, "[Odinagent.cc] Lvap set\n");

  return 0;
}


/**
 * Invoking this implies knocking
 * a client off the access point
 */
int
OdinAgent::remove_vap (EtherAddress sta_mac)
{
  if (_debug_level % 10 > 0) {
    if (_debug_level / 10 == 1)    // demo mode. I print more visual information
      fprintf(stderr, "##################################################################\n");

    fprintf(stderr, "[Odinagent.cc] remove_lvap (%s)\n", sta_mac.unparse_colon().c_str());

    if (_debug_level / 10 == 1)    // demo mode. I print more visual information
      fprintf(stderr, "##################################################################\n\n");
  }

  HashTable<EtherAddress, OdinStationState>::iterator it = _sta_mapping_table.find (sta_mac);

  // VAP doesn't exist on this node. Ignore.
  if (it == _sta_mapping_table.end())
    return -1;

  // We need to un-prime the ARP responders
  // FIXME: Don't rely on labelled name
  Router *r = router();
  HandlerCall::call_write (r->find("fh_arpr"), "remove", it.value()._sta_ip_addr_v4.unparse() + "/32");
  HandlerCall::call_write (r->find("arp_resp"), "remove", it.value()._sta_ip_addr_v4.unparse() + "/32");

  _sta_mapping_table.erase (it);

  // Remove this VAP's BSSID from the mask
  compute_bssid_mask();

  // Stop beacon generator if this was the last
  // LVAP
  if (_sta_mapping_table.size() == 0) {
    _beacon_timer.unschedule();
  }


  return 0;
}


/**
* Receive a deauthentication packet
*/
void
OdinAgent::recv_deauth (Packet *p) {

        struct click_wifi *w = (struct click_wifi *) p->data();
        //uint8_t *ptr;
        //ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

        /*uint16_t algo = le16_to_cpu(*(uint16_t *) ptr);
        ptr += 2;

        uint16_t seq = le16_to_cpu(*(uint16_t *) ptr);
        ptr += 2;

        uint16_t status = le16_to_cpu(*(uint16_t *) ptr);
        ptr += 2;
*/
        EtherAddress src = EtherAddress(w->i_addr2);

        //If we're not aware of this LVAP, ignore
        if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
                p->kill();
                return;
        }

/*
        if (algo != WIFI_FC0_SUBTYPE_DEAUTH) {
                // click_chatter("%{element}: auth %d from %s not supported\n",
                // this,
                // algo,
                // src.unparse().c_str());
                p->kill();
                return;
        }
*/
        if (_debug_level % 10 > 0)
          fprintf(stderr, "[Odinagent.cc] STA ---> AP (Deauthentication)\n");

        // Notify the master
        StringAccum sa;
        sa << "deauthentication " << src.unparse_colon().c_str() << "\n";

        String payload = sa.take_string();
        WritablePacket *odin_disconnect_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
        output(3).push(odin_disconnect_packet);

        p->kill();

        print_stations_state();

        return;
}


/**
 * Handle a beacon frame to return its SSID value
 */
String 
OdinAgent::recv_beacon (Packet *p)
{

  //struct click_wifi *w = (struct click_wifi *) p->data();
  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  uint8_t *end  = (uint8_t *) p->data() + p->length();

  uint8_t *ssid_l = NULL;
  //uint8_t *rates_l = NULL; commented becaus it was not used

  while (ptr < end) {
    switch (*ptr) {
    case WIFI_ELEMID_SSID:
    ssid_l = ptr;
    break;
    case WIFI_ELEMID_RATES:
    //rates_l = ptr;
    break;
    default:
    break;
    }
    ptr += ptr[1] + 2;
  }

  String ssid = "";
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  }

  return ssid;
}








/**
 * Handle a probe request. This code is
 * borrowed from the ProbeResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::recv_probe_request (Packet *p)
{

  struct click_wifi *w = (struct click_wifi *) p->data();
  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  uint8_t *end  = (uint8_t *) p->data() + p->length();

  uint8_t *ssid_l = NULL;
  //uint8_t *rates_l = NULL; commented becaus it was not used

  while (ptr < end) {
  switch (*ptr) {
  case WIFI_ELEMID_SSID:
    ssid_l = ptr;
    break;
  case WIFI_ELEMID_RATES:
    //rates_l = ptr;
    break;
  default:
    break;
  }
  ptr += ptr[1] + 2;

  }

  String ssid = "";
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  }

  EtherAddress src = EtherAddress(w->i_addr2);

  if (_debug_level % 10 > 1)
    fprintf(stderr, "[Odinagent.cc] SSID frame: %s SSID AP: %s\n", ssid.c_str(), _ssid_agent_string.c_str());

  //If we're not aware of this LVAP, then send to the controller.
  //If the SSID is hidden, then it will only send responses to the active scans targetted to the _ssid_agent_string
  if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
    if (((ssid == "") && _hidden == 0 ) || (ssid == _ssid_agent_string)) {  //if the ssid is blank (broadcast probe) or it is targetted to our SSID, forward it to the controller
    if (_debug_level % 10 > 1)
      fprintf(stderr, "[Odinagent.cc] Received probe request: not aware of this LVAP -> probe req sent to the controller\n");
    StringAccum sa;
    sa << "probe " << src.unparse_colon().c_str() << " " << ssid << "\n";
    String payload = sa.take_string();
    WritablePacket *odin_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
    output(3).push(odin_probe_packet);
    _packet_buffer.set (src, ssid);
    }

    p->kill();
    return;
  }

  OdinStationState oss = _sta_mapping_table.get (src);

  /* If the client is performing an active scan, then
   * then respond from all available SSIDs. Else, if
   * the client is probing for a particular SSID, check
   * if we're indeed hosting that SSID and respond
   * accordingly. */
  if (ssid == "") {
      for (int i = 0; i < oss._vap_ssids.size(); i++) {
          send_beacon(src, oss._vap_bssid, oss._vap_ssids[i], true);
      }
  }

  //specific probe request
  if (ssid != "") {
    for (int i = 0; i < oss._vap_ssids.size(); i++) {
      if (oss._vap_ssids[i] == ssid) {
        if (_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc] Received probe request, sending beacon...\n");
        send_beacon(src, oss._vap_bssid, ssid, true);
        break;
      }
    }
  }

  p->kill();
  return;
}


/** 
 * Send a beacon/probe-response. This code is
 * borrowed from the BeaconSource element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table.
 * 
 * Modified from the original in order to include a 
 * CSA-Beacon (channel switch announcement)
 * which is sent to a client but does not change the 
 * agent channel.
 * 
 * @author Luis Sequeira <sequeira@unizar.es>
 * 
 */
void
OdinAgent::send_beacon (EtherAddress dst, EtherAddress bssid, String my_ssid, bool probe) {
    
    HashTable<EtherAddress, int>::const_iterator it = _csa_table.find(dst);
    
  // if ( _csa == true && !(probe) ) { // For channel switch announcement
    if (it != _csa_table.end() && !(probe)) {
        
        int count_csa_beacon = it.value();
    
    if (_debug_level % 10 > 0)
      fprintf(stderr, "[Odinagent.cc] #################### Sending csa beacon (%i) to STA: %s\n",count_csa_beacon, dst.unparse_colon().c_str());// For testing only
    
    /* send_beacon after channel switch */
    Vector<int> rates = _rtable->lookup(bssid);

    /* order elements by standard
     * needed by sloppy 802.11b driver implementations
     * to be able to connect to 802.11g APs */
    int max_len = sizeof (struct click_wifi) +
      8 +                  /* timestamp */
      2 +                  /* beacon interval */
      2 +                  /* cap_info */
      2 + my_ssid.length() + /* ssid */
      2 + WIFI_RATES_MAXSIZE +  /* rates */
      2 + 1 +              /* ds parms */
      2 + 4 +              /* tim */
      5 +      /* csa */
      /* 802.11g Information fields */
      2 + WIFI_RATES_MAXSIZE +  /* xrates */
      0;

    
    WritablePacket *p = Packet::make(max_len);

    if (p == 0)
      return;

    struct click_wifi *w = (struct click_wifi *) p->data();

    w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT;
    if (probe) {
      w->i_fc[0] |= WIFI_FC0_SUBTYPE_PROBE_RESP;
    } else {
      w->i_fc[0] |=  WIFI_FC0_SUBTYPE_BEACON;
    }

    w->i_fc[1] = WIFI_FC1_DIR_NODS;

    memcpy(w->i_addr1, dst.data(), 6);
    memcpy(w->i_addr2, bssid.data(), 6);
    memcpy(w->i_addr3, bssid.data(), 6);

    w->i_dur = 0;
    w->i_seq = 0;

    uint8_t *ptr;

    ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
    int actual_length = sizeof (struct click_wifi);


    /* timestamp is set in the hal. ??? */
    memset(ptr, 0, 8);
    ptr += 8;
    actual_length += 8;
    
    /*This interval  is the BI expected in the other channel by the STA*/ // FIXME
    _interval_ms=_interval_ms_burst;

    uint16_t beacon_int = (uint16_t) _interval_ms; // FIXME
    *(uint16_t *)ptr = cpu_to_le16(beacon_int);
    ptr += 2;
    actual_length += 2;

    uint16_t cap_info = 0;
    cap_info |= WIFI_CAPINFO_ESS;
    *(uint16_t *)ptr = cpu_to_le16(cap_info);
    ptr += 2;
    actual_length += 2;

    /* ssid */
    ptr[0] = WIFI_ELEMID_SSID;
    ptr[1] = my_ssid.length();
    memcpy(ptr + 2, my_ssid.data(), my_ssid.length());
    ptr += 2 + my_ssid.length();
    actual_length += 2 + my_ssid.length();

    /* rates */
    ptr[0] = WIFI_ELEMID_RATES;
    ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
    for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
      ptr[2 + x] = (uint8_t) rates[x];

      if (rates[x] == 2) {
        ptr [2 + x] |= WIFI_RATE_BASIC;
      }

    }
    ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
    actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());


    /* channel */
    ptr[0] = WIFI_ELEMID_DSPARMS;
    ptr[1] = 1;
    ptr[2] = (uint8_t) _channel; 
    ptr += 2 + 1;
    actual_length += 2 + 1;

    /* tim */

    ptr[0] = WIFI_ELEMID_TIM;
    ptr[1] = 4;

    ptr[2] = 0;     //count
    ptr[3] = 1;     //period
    ptr[4] = 0;     //bitmap control
    ptr[5] = 0;     //paritial virtual bitmap
    ptr += 2 + 4;   // Channel Switch Count
    actual_length += 2 + 4;
    
    /* csa */
    
    ptr[0] = 37;  // Element ID 
    ptr[1] = 3;   // Length
    ptr[2] = 0;   // Channel Switch Mode
    ptr[3] = _new_channel;   // New Channel Number
    //ptr[4] = _count_csa_beacon--; // Countdown
    ptr[4] = count_csa_beacon--; // Countdown // FIXME
    ptr += 5;
    actual_length += 5;

    /* 802.11g fields */
    /* extended supported rates */
    int num_xrates = rates.size() - WIFI_RATE_SIZE;
    if (num_xrates > 0) {
      /* rates */
      ptr[0] = WIFI_ELEMID_XRATES;
      ptr[1] = num_xrates;
      for (int x = 0; x < num_xrates; x++) {
        ptr[2 + x] = (uint8_t) rates[x + WIFI_RATE_SIZE];

        if (rates[x + WIFI_RATE_SIZE] == 2) {
          ptr [2 + x] |= WIFI_RATE_BASIC;
        }

      }
      ptr += 2 + num_xrates;
      actual_length += 2 + num_xrates;
    }

    p->take(max_len - actual_length);

    Timestamp now = Timestamp::now();
    Timestamp old =  _mean_table.get (dst);

    if (old != NULL) {

      Timestamp diff = now - old;
      double new_val = diff.sec() * 1000000000 + diff.usec();

      if (_debug_level % 10 > 1)
        fprintf(stderr, "[Odinagent.cc] Out: %f\n", new_val);

      _num_mean++;
      double delta = new_val - _mean;
      _mean = _mean + delta/_num_mean;
      _m2 = _m2 + delta * (new_val - _mean);
      _mean_table.erase (dst);
    }

    output(0).push(p);
    _interval_ms = _interval_ms_default; // FIXME
      _csa_table.erase(it.key());
      if ( count_csa_beacon >= 0 ) {
        _csa_table.set(dst,count_csa_beacon);
      }
  }

  else { // For NO channel switch announcement or probe responder
    
  /* For testing only */
  /*if ( probe ) {
    if (_debug_level % 10 > 1)
      fprintf(stderr, "[Odinagent.cc] Sending Probe Response\n");
  }
  else {
    if (_debug_level % 10 >1)
      fprintf(stderr, "[Odinagent.cc] Sending beacon for NO csa\n");
  }*/
    
  /* send_beacon before channel switch or probe response */
  Vector<int> rates = _rtable->lookup(bssid);

  /* order elements by standard
   * needed by sloppy 802.11b driver implementations
   * to be able to connect to 802.11g APs */
  int max_len = sizeof (struct click_wifi) +
    8 +                  /* timestamp */
    2 +                  /* beacon interval */
    2 +                  /* cap_info */
    2 + my_ssid.length() + /* ssid */
    2 + WIFI_RATES_MAXSIZE +  /* rates */
    2 + 1 +              /* ds parms */
    2 + 4 +              /* tim */
    /* 802.11g Information fields */
    2 + WIFI_RATES_MAXSIZE +  /* xrates */
    0;


  WritablePacket *p = Packet::make(max_len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT;
  if (probe) {
    w->i_fc[0] |= WIFI_FC0_SUBTYPE_PROBE_RESP;
  } else {
    w->i_fc[0] |=  WIFI_FC0_SUBTYPE_BEACON;
  }

  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);

  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof (struct click_wifi);


  /* timestamp is set in the hal. ??? */
  memset(ptr, 0, 8);
  ptr += 8;
  actual_length += 8;

  uint16_t beacon_int = (uint16_t) _interval_ms;
  *(uint16_t *)ptr = cpu_to_le16(beacon_int);
  ptr += 2;
  actual_length += 2;

  uint16_t cap_info = 0;
  cap_info |= WIFI_CAPINFO_ESS;
  *(uint16_t *)ptr = cpu_to_le16(cap_info);
  ptr += 2;
  actual_length += 2;

  /* ssid */
  ptr[0] = WIFI_ELEMID_SSID;
  ptr[1] = my_ssid.length();
  memcpy(ptr + 2, my_ssid.data(), my_ssid.length());
  ptr += 2 + my_ssid.length();
  actual_length += 2 + my_ssid.length();

  /* rates */
  ptr[0] = WIFI_ELEMID_RATES;
  ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
    ptr[2 + x] = (uint8_t) rates[x];

    if (rates[x] == 2) {
      ptr [2 + x] |= WIFI_RATE_BASIC;
    }

  }
  ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());


  /* channel */
  ptr[0] = WIFI_ELEMID_DSPARMS;
  ptr[1] = 1;
  ptr[2] = (uint8_t) _channel;
  ptr += 2 + 1;
  actual_length += 2 + 1;

  /* tim */

  ptr[0] = WIFI_ELEMID_TIM;
  ptr[1] = 4;

  ptr[2] = 0; //count
  ptr[3] = 1; //period
  ptr[4] = 0; //bitmap control
  ptr[5] = 0; //paritial virtual bitmap
  ptr += 2 + 4;
  actual_length += 2 + 4;

  /* 802.11g fields */
  /* extended supported rates */
  int num_xrates = rates.size() - WIFI_RATE_SIZE;
  if (num_xrates > 0) {
    /* rates */
    ptr[0] = WIFI_ELEMID_XRATES;
    ptr[1] = num_xrates;
    for (int x = 0; x < num_xrates; x++) {
      ptr[2 + x] = (uint8_t) rates[x + WIFI_RATE_SIZE];

      if (rates[x + WIFI_RATE_SIZE] == 2) {
        ptr [2 + x] |= WIFI_RATE_BASIC;
      }

    }
    ptr += 2 + num_xrates;
    actual_length += 2 + num_xrates;
  }

  p->take(max_len - actual_length);

  Timestamp now = Timestamp::now();
  Timestamp old =  _mean_table.get (dst);

  if (old != NULL) {

    Timestamp diff = now - old;
    double new_val = diff.sec() * 1000000000 + diff.usec();

    if (_debug_level % 10 > 1)
      fprintf(stderr, "[Odinagent.cc] Out: %f\n", new_val);

    _num_mean++;
    double delta = new_val - _mean;
    _mean = _mean + delta/_num_mean;
    _m2 = _m2 + delta * (new_val - _mean);
    _mean_table.erase (dst);
  }

  output(0).push(p);
}
    

  /** 
   * Give some time before channel switch 
   * Used for testing only
   */
  /*if ( _csa_count == 0 ) {
    _csa = true;
    if (_debug_level % 10 > 1)
      fprintf(stderr, "[Odinagent.cc] _csa is true\n");
  }
  else {
    _csa_count--;
    if (_debug_level % 10 > 1)
      fprintf(stderr, "[Odinagent.cc] Decreasing _csa_count = %d\n", _csa_count);
  }*/
  
  /* Reset counters after channel switch */
  /*if ( _count_csa_beacon < 0 ) {
  if (it.value() < 0 ) {
    _count_csa_beacon = _count_csa_beacon_default;
  //_csa_count = _csa_count_default;
  //_csa = false;
    _csa_table.erase(it.key());
  }*/
  

}


/**
* Receive an Open Auth request. This code is
* borrowed from the OpenAuthResponder element
* and is modified to retrieve the BSSID/SSID
* from the sta_mapping_table
*/
void
OdinAgent::recv_open_auth_request (Packet *p) {
    //if (_debug_level % 10 > 1)
    //  fprintf(stderr, "[Odinagent.cc] Inside recv_auth_request\n");

    struct click_wifi *w = (struct click_wifi *) p->data();
    uint8_t *ptr;
    ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

    uint16_t algo = le16_to_cpu(*(uint16_t *) ptr);
    ptr += 2;

    uint16_t seq = le16_to_cpu(*(uint16_t *) ptr);
    ptr += 2;

    //uint16_t status = le16_to_cpu(*(uint16_t *) ptr); commented because it was not used
    ptr += 2;

    EtherAddress src = EtherAddress(w->i_addr2);
    EtherAddress dst = EtherAddress(w->i_addr1);

    //If we're not aware of this LVAP, ignore
    if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
        p->kill();
        return;
    }

    if (algo != WIFI_AUTH_ALG_OPEN) {
        // click_chatter("%{element}: auth %d from %s not supported\n",
        // this,
        // algo,
        // src.unparse().c_str());
        p->kill();
        return;
    }

    if (seq != 1) {
        // click_chatter("%{element}: auth %d weird sequence number %d\n",
        // this,
        // algo,
        // seq);
        p->kill();
        return;
    }

    if (_debug_level % 10 > 0) {
      if (_debug_level / 10 == 1)    // demo mode. I print more visual information
        fprintf(stderr, "##################################################################\n");

      fprintf(stderr, "[Odinagent.cc] OpenAuth request     STA (%s) ----> AP (%s)\n", src.unparse_colon().c_str(), dst.unparse_colon().c_str());
    }
    send_open_auth_response(src, 2, WIFI_STATUS_SUCCESS);

    p->kill();
    return;
}


/**
* Send an Open Auth request. This code is
* borrowed from the OpenAuthResponder element
* and is modified to retrieve the BSSID/SSID
* from the sta_mapping_table
*/
void
OdinAgent::send_open_auth_response (EtherAddress dst, uint16_t seq, uint16_t status) {

    OdinStationState oss = _sta_mapping_table.get (dst);

    int len = sizeof (struct click_wifi) +
    2 +                  /* alg */
    2 +                  /* seq */
    2 +                  /* status */
    0;

    WritablePacket *p = Packet::make(len);

    if (p == 0)
        return;

        struct click_wifi *w = (struct click_wifi *) p->data();

        w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT | WIFI_FC0_SUBTYPE_AUTH;
        w->i_fc[1] = WIFI_FC1_DIR_NODS;

        memcpy(w->i_addr1, dst.data(), 6);
        memcpy(w->i_addr2, oss._vap_bssid.data(), 6);
        memcpy(w->i_addr3, oss._vap_bssid.data(), 6);

        EtherAddress src = EtherAddress(w->i_addr2);

        w->i_dur = 0;
        w->i_seq = 0;

        uint8_t *ptr;

        ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

        *(uint16_t *)ptr = cpu_to_le16(WIFI_AUTH_ALG_OPEN);
        ptr += 2;

        *(uint16_t *)ptr = cpu_to_le16(seq);
        ptr += 2;

        *(uint16_t *)ptr = cpu_to_le16(status);
        ptr += 2;

        output(0).push(p);

        if (_debug_level % 10 > 0)
            fprintf(stderr, "[Odinagent.cc] OpenAuth response    STA (%s) <---- AP (%s)\n", dst.unparse_colon().c_str(), src.unparse_colon().c_str());
    }

/**
 * Receive an association request. This code is
 * borrowed from the AssociationResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::recv_assoc_request (Packet *p) {
  //if (_debug_level % 10 > 1)
  //  fprintf(stderr, "[Odinagent.cc] Inside recv_assoc_request\n");

  struct click_wifi *w = (struct click_wifi *) p->data();

  EtherAddress dst = EtherAddress(w->i_addr1);
  EtherAddress src = EtherAddress(w->i_addr2);
  //EtherAddress bssid = EtherAddress(w->i_addr3); commented because it was not used

  // Do not respond to node who's LVAP we're not
  // hosting.
  if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
    p->kill();
    return;
  }

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  /*capabilty */
  //uint16_t capability = le16_to_cpu(*(uint16_t *) ptr); commented because it was not used
  ptr += 2;

  /* listen interval */
  //uint16_t lint = le16_to_cpu(*(uint16_t *) ptr); commented because it was not used
  ptr += 2;

  uint8_t *end  = (uint8_t *) p->data() + p->length();

  uint8_t *ssid_l = NULL;
  uint8_t *rates_l = NULL;

  while (ptr < end) {
    switch (*ptr) {
      case WIFI_ELEMID_SSID:
          ssid_l = ptr;
          break;
      case WIFI_ELEMID_RATES:
          rates_l = ptr;
          break;
      default:
          {
            break;
          }
    }
    ptr += ptr[1] + 2;
  }

  Vector<int> basic_rates;
  Vector<int> rates;
  Vector<int> all_rates;
  if (rates_l) {
    for (int x = 0; x < WIFI_MIN((int)rates_l[1], WIFI_RATES_MAXSIZE); x++) {
        uint8_t rate = rates_l[x + 2];

        if (rate & WIFI_RATE_BASIC) {
      basic_rates.push_back((int)(rate & WIFI_RATE_VAL));
        } else {
      rates.push_back((int)(rate & WIFI_RATE_VAL));
        }
          all_rates.push_back((int)(rate & WIFI_RATE_VAL));
    }
  }

  OdinStationState *oss = _sta_mapping_table.get_pointer (src);

  if (oss == NULL) {
    p->kill();
    return;
  }

  String ssid;
  String my_ssid = oss->_vap_ssids[0];
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  } else {
    /* there was no element or it has zero length */
    ssid = "";
  }

  uint16_t associd = 0xc000 | _associd++;
  if (_debug_level % 10 > 0)
    fprintf(stderr, "[Odinagent.cc] Association request  STA (%s) ----> AP (%s)\n", src.unparse_colon().c_str(), dst.unparse_colon().c_str());

  send_assoc_response(src, WIFI_STATUS_SUCCESS, associd);
  p->kill();
  return;
}


/**
 * Send an association request. This code is
 * borrowed from the AssociationResponder element
 * and is modified to retrieve the BSSID/SSID
 * from the sta_mapping_table
 */
void
OdinAgent::send_assoc_response (EtherAddress dst, uint16_t status, uint16_t associd) {
  EtherAddress bssid = _sta_mapping_table.get (dst)._vap_bssid;

  Vector<int> rates = _rtable->lookup(bssid);
  int max_len = sizeof (struct click_wifi) +
    2 +                  /* cap_info */
    2 +                  /* status  */
    2 +                  /* assoc_id */
    2 + WIFI_RATES_MAXSIZE +  /* rates */
    2 + WIFI_RATES_MAXSIZE +  /* xrates */
    0;

  WritablePacket *p = Packet::make(max_len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT | WIFI_FC0_SUBTYPE_ASSOC_RESP;
  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);

  EtherAddress src = EtherAddress(w->i_addr2);

  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof(struct click_wifi);

  uint16_t cap_info = 0;
  cap_info |= WIFI_CAPINFO_ESS;
  *(uint16_t *)ptr = cpu_to_le16(cap_info);
  ptr += 2;
  actual_length += 2;

  *(uint16_t *)ptr = cpu_to_le16(status);
  ptr += 2;
  actual_length += 2;

  *(uint16_t *)ptr = cpu_to_le16(associd);
  ptr += 2;
  actual_length += 2;


  /* rates */
  ptr[0] = WIFI_ELEMID_RATES;
  ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
    ptr[2 + x] = (uint8_t) rates[x];

    if (rates[x] == 2) {
      ptr [2 + x] |= WIFI_RATE_BASIC;
    }

  }
  ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());


  int num_xrates = rates.size() - WIFI_RATE_SIZE;
  if (num_xrates > 0) {
    /* rates */
    ptr[0] = WIFI_ELEMID_XRATES;
    ptr[1] = num_xrates;
    for (int x = 0; x < num_xrates; x++) {
      ptr[2 + x] = (uint8_t) rates[x + WIFI_RATE_SIZE];

      if (rates[x + WIFI_RATE_SIZE] == 2) {
  ptr [2 + x] |= WIFI_RATE_BASIC;
      }

    }
    ptr += 2 + num_xrates;
    actual_length += 2 + num_xrates;
  }

  p->take(max_len - actual_length);

  output(0).push(p);

  if (_debug_level % 10 > 0) {
    fprintf(stderr, "[Odinagent.cc] Association response STA (%s) <---- AP (%s)\n", dst.unparse_colon().c_str(), src.unparse_colon().c_str());

    if (_debug_level / 10 == 1)    // demo mode. I print more visual information
      fprintf(stderr, "##################################################################\n\n");

  }
  //Notify the master that a client has completed the auth/assoc procedure so it can stop the timer and prevent it from removing the lvap
  StringAccum sa;
  sa << "association " << dst.unparse_colon().c_str() << "\n";

  String payload = sa.take_string();
  WritablePacket *odin_association_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
  output(3).push(odin_association_packet);

  //print_stations_state();


}

/**
 * Encapsulate an ethernet frame with a 802.11 header.
 * Borrowed from WifiEncap element.
 * NOTE: This method uses the FromDS mode (0x02)
 */
Packet*
OdinAgent::wifi_encap (Packet *p, EtherAddress bssid)
{
  EtherAddress src;
  EtherAddress dst;

  uint16_t ethtype;
  WritablePacket *p_out = 0;

  if (p->length() < sizeof(struct click_ether)) {
    // click_chatter("%{element}: packet too small: %d vs %d\n",
    //   this,
    //   p->length(),
    //   sizeof(struct click_ether));

    p->kill();
    return 0;

  }

  click_ether *eh = (click_ether *) p->data();
  src = EtherAddress(eh->ether_shost);
  dst = EtherAddress(eh->ether_dhost);
  memcpy(&ethtype, p->data() + 12, 2);

  p_out = p->uniqueify();
  if (!p_out) {
    return 0;
  }


  p_out->pull(sizeof(struct click_ether));
  p_out = p_out->push(sizeof(struct click_llc));

  if (!p_out) {
    return 0;
  }

  memcpy(p_out->data(), WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
  memcpy(p_out->data() + 6, &ethtype, 2);

  if (!(p_out = p_out->push(sizeof(struct click_wifi))))
      return 0;
  struct click_wifi *w = (struct click_wifi *) p_out->data();

  memset(p_out->data(), 0, sizeof(click_wifi));
  w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
  w->i_fc[1] = 0;
  w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & WIFI_FC1_DIR_FROMDS);

  // Equivalent to mode 0x02
  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, src.data(), 6);

  return p_out;
}


/**
 * Every time a packet is transmitted, the transmission
 * statistics have to be updated
 */
void
OdinAgent::update_tx_stats(Packet *p)
{
  struct click_wifi *w = (struct click_wifi *) p->data();
  EtherAddress dst = EtherAddress(w->i_addr1);       // Get the MAC destination address. In this case it is the first MAC address

  //struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);

  StationStats stat;
  HashTable<EtherAddress, StationStats>::const_iterator it = _tx_stats.find(dst);  // find the destination address in the stats table

  // if the station does not have a statistics variable, create it
  if (it == _tx_stats.end()) {
    stat = StationStats();

    stat._time_first_packet.assign_now();  // update the value of the first received packet
  }
  else
    stat = it.value();

  // the rate is directly read from the Click configuration file
  //stat._rate = ceh->rate;
  stat._rate = _tx_rate;

  // we are not currently modifying per-packet transmission power
  //so calculating the average makes no sense
  //stat._signal = ceh->rssi + _signal_offset;
  stat._signal = _tx_power + 256;   // we add 256, as this is the usual way for storing the power

  // we are not reading the noise value, so assign a 0
  //stat._noise = ceh->silence;
  stat._noise = 0;

  // read the length of the packet
  stat._len_pkt = p->length();
  
  stat._packets++; // increase the number of packets

  // Calculate the averaged statistics
  stat._avg_rate = stat._avg_rate + ((stat._rate*500 - stat._avg_rate)/stat._packets); // rate in Kbps
  
  /* as we are not setting different values for each packet, we do not have to calculate this
  // Calculate the value of the signal, converting from dBm to mW and back
  double signal_mW;
  double avg_signal_mW;
  signal_mW = pow (10, (stat._signal - 256) / 10);
  if (first_packet)  // if this is the first packet, the previous average will be 0
    avg_signal_mW  = 0;
  else 
    avg_signal_mW  = pow (10, stat._avg_signal / 10);
  avg_signal_mW = avg_signal_mW + ((signal_mW - avg_signal_mW)/stat._packets);
  stat._avg_signal = 10 * log10 (avg_signal_mW); // signal in dBm
  //stat._avg_signal = stat._avg_signal + ((stat._signal - 256 - stat._avg_signal)/stat._packets); // signal in dBm
  stat._avg_signal = 0;  // we are not currently modifying per-packet transmission power so calculating the average makes no sense
  */
  stat._avg_signal = _tx_power; // in dBm
  
  stat._avg_len_pkt = stat._avg_len_pkt + ((stat._len_pkt - stat._avg_len_pkt)/stat._packets); // length in bytes
  stat._air_time = stat._air_time + ((double)(8*stat._len_pkt) / (double)(stat._rate*500)); // time used by this packet (in ms)

  // store the timestamp of this packet as the one of the last packet
  stat._time_last_packet.assign_now();
  stat._equipment = "AP";

  /*
  if (_debug_level % 10 > 1){
        FILE * fp;
        fp = fopen ("/root/spring/shared/updated_stats.txt", "w");
        fprintf(fp, "* update_rx_stats: src = %s, rate = %i, noise = %i, signal = %i (%i dBm)\n", src.unparse_colon().c_str(), stat._rate, stat._noise, stat._signal, (stat._signal - 128)*-1); //-(value - 128)
        fclose(fp);
  }
  */

  // update the statistics table
  _tx_stats.set (dst, stat);
}

/**
 * Every time a packet is received, the reception
 * statistics have to be updated
 */
void
OdinAgent::update_rx_stats(Packet *p)
{
  struct click_wifi *w = (struct click_wifi *) p->data();
  EtherAddress src = EtherAddress(w->i_addr2);

  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);

  StationStats stat;
  bool first_packet = false; // it will be true if the packet is the first one used for the average
  HashTable<EtherAddress, StationStats>::const_iterator it = _rx_stats.find(src);

  // if the station does not have a statistics variable, create it
  if (it == _rx_stats.end()) {
    stat = StationStats();

  stat._time_first_packet.assign_now();  // update the value of the first received packet
  first_packet = true;
  }
  else
    stat = it.value();

  stat._rate = ceh->rate;
  stat._signal = ceh->rssi + _signal_offset;
  stat._noise = ceh->silence;
  stat._len_pkt = p->length();
  
  stat._packets++; // increase the number of packets

  // Calculate the averaged statistics
  stat._avg_rate = stat._avg_rate + ((stat._rate*500 - stat._avg_rate)/stat._packets); // rate in Kbps

  // Calculate the value of the signal, converting from dBm to mW and back
  double signal_mW;
  double avg_signal_mW;
  signal_mW = pow (10, (stat._signal - 256) / 10);
  if (first_packet)  // if this is the first packet, the previous average will be 0
    avg_signal_mW  = 0;
  else 
    avg_signal_mW  = pow (10, stat._avg_signal / 10);
  avg_signal_mW = avg_signal_mW + ((signal_mW - avg_signal_mW)/stat._packets);
  stat._avg_signal = 10 * log10 (avg_signal_mW); // signal in dBm
  
  stat._avg_len_pkt = stat._avg_len_pkt + ((stat._len_pkt - stat._avg_len_pkt)/stat._packets); // length in bytes
  stat._air_time = stat._air_time + ((double)(8*stat._len_pkt) / (double)(stat._rate*500)); // time used by this packet (in ms)

  // store the timestamp of this packet as the one of the last packet
  stat._time_last_packet.assign_now();

  /*
  if (_debug_level % 10 > 1){
        FILE * fp;
        fp = fopen ("/root/spring/shared/updated_stats.txt", "w");
        fprintf(fp, "* update_rx_stats: src = %s, rate = %i, noise = %i, signal = %i (%i dBm)\n", src.unparse_colon().c_str(), stat._rate, stat._noise, stat._signal, (stat._signal - 128)*-1); //-(value - 128)
        fclose(fp);
  }
  */
  
  uint8_t fromDs;
  
  fromDs = w->i_fc[1] & WIFI_FC1_DIR_FROMDS;

  if (fromDs == WIFI_FC1_DIR_FROMDS) {
    stat._equipment = "AP";
      
  }else{
    stat._equipment = "STA";
  }
  match_against_subscriptions(stat, src);

  // update the statistics table
  _rx_stats.set (src, stat);
}



/**
 * Every time a packet is received by scanning interface, the reception
 * statistics have to be updated in scanned_station_stats HashTable
 */
void
OdinAgent::update_scanned_station_stats(Packet *p)
{
  struct click_wifi *w = (struct click_wifi *) p->data();
  EtherAddress src = EtherAddress(w->i_addr2);

  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);

  StationStats stat;
  bool first_packet = false; // it will be true if the packet is the first one used for the average
  HashTable<EtherAddress, StationStats>::const_iterator it = _scanned_station_stats.find(src);

  // if the station does not have a statistics variable, create it
  if (it == _scanned_station_stats.end()) {
    stat = StationStats();

  stat._time_first_packet.assign_now();  // update the value of the first received packet
  first_packet = true;
  }
  else
    stat = it.value();

  stat._rate = ceh->rate;
  stat._signal = ceh->rssi + _signal_offset;
  stat._noise = ceh->silence;
  stat._len_pkt = p->length();
  
  stat._packets++; // increase the number of packets

  // Calculate the averaged statistics
  stat._avg_rate = stat._avg_rate + ((stat._rate*500 - stat._avg_rate)/stat._packets); // rate in Kbps

  // Calculate the value of the signal, converting from dBm to mW and back
  double signal_mW;
  double avg_signal_mW;
  signal_mW = pow (10, (stat._signal - 256) / 10);
  if (first_packet)  // if this is the first packet, the previous average will be 0
    avg_signal_mW  = 0;
  else 
    avg_signal_mW  = pow (10, stat._avg_signal / 10);
  avg_signal_mW = avg_signal_mW + ((signal_mW - avg_signal_mW)/stat._packets);
  stat._avg_signal = 10 * log10 (avg_signal_mW); // signal in dBm
  
  stat._avg_len_pkt = stat._avg_len_pkt + ((stat._len_pkt - stat._avg_len_pkt)/stat._packets); // length in bytes
  stat._air_time = stat._air_time + ((double)(8*stat._len_pkt) / (double)(stat._rate*500)); // time used by this packet (in ms)

  // store the timestamp of this packet as the one of the last packet
  stat._time_last_packet.assign_now();

  uint8_t fromDs;
  
  fromDs = w->i_fc[1] & WIFI_FC1_DIR_FROMDS;

  if (fromDs == WIFI_FC1_DIR_FROMDS) {
    stat._equipment = "AP";
      
  }else{
    stat._equipment = "STA";
  }

 // update the statistics table
  _scanned_station_stats.set (src, stat);
}

/**
 * Check if the file where mon power is saved is already created
 */
inline bool OdinAgent::exists_file (String name) {
  struct stat buffer;   
  return (stat (name.c_str(), &buffer) == 0); 
}

/**
 * Save to file all the packet statistics
 */
void
OdinAgent::stats_to_file(Packet *p, String filename)
{
    // Always after a similar check
    /*if (p->length() < sizeof(struct click_wifi)) {
      p->kill();
      return;
  }*/
    std::ofstream fp;
    char rssi [3];
    char rate [4];
    char seq [6];
    
    if(!exists_file(filename.c_str())){
        fp.open ( filename.c_str() , std::ofstream::out);
        if (fp.is_open()){
            fp << "Time(sec);Src;Dst;Bssid;Seq;Rate(Mbps);RadioTapPowerLevel;\n";
        }else{std::cout << "Unable to open file";}
    }else{
        fp.open ( filename.c_str() , std::ofstream::out | std::ofstream::app);
    }
    struct click_wifi *w = (struct click_wifi *) p->data();
    struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
    Timestamp time;
    time.assign_now();                                  // FIXME use new radiotapdecap param
    EtherAddress dst = EtherAddress(w->i_addr1);
    EtherAddress src = EtherAddress(w->i_addr2);
    EtherAddress bssid = EtherAddress(w->i_addr3);
    // FIXME add all the radiotapdecap params
    sprintf (rssi, "%d",ceh->rssi); // convert to str
    sprintf (rate, "%d",ceh->rate/2); // convert to str
    sprintf (seq, "%d",le16_to_cpu(w->i_seq) >> WIFI_SEQ_SEQ_SHIFT); // convert to str, seq is little endian and once converted first byte is fragment
    if (fp.is_open()){
        fp << time.sec() << "," << time.subsec() << ";" << src.unparse_colon().c_str() << ";" << dst.unparse_colon().c_str() << ";" << bssid.unparse_colon().c_str() << ";" << seq << ";" << rate << ";" << rssi << ";\n";
    }else{
        std::cout << "Unable to open file";
    }
    fp.close();
}

/**
 * This element has three input ports and 4 output ports.
 *
 * In-port-0: Any 802.11 encapsulated frame. Expected
 *            to be coming from a physical device
 * In-port-1: Any ethernet encapsulated frame. Expected
 *            to be coming from a tap device
 * In-port-2: Any 802.11 encapsulated frame. Used exclusively
 *         for scanning clients.
 *
 * Out-port-0: If in-port-0, and packet was a management frame,
 *             then send out management response.
 * Out-port-1: If in-port-0, and packet was a data frame,
 *             then push data frame to the higher layers.
 * Out-port-2: If in-port-1, and packet was destined to a client
 *              for which we have a VAP, then let it through.
 * Out-port-3: Used exclusively to talk to a Socket to be used
 *             to communicate with the OdinMaster. Should be removed
 *             later.
 */
void
OdinAgent::push(int port, Packet *p)
{
  // If port == 0, then the packet is an 802.11
  // frame, and could be of type data or Mgmnt.
  // We filter data frames by available VAPs,
  // and we handle Mgmnt frames accordingly.

  uint8_t type;
  uint8_t subtype;

  if (port == 0) {
      
    
  /****************************************************************************
  *****************************************************************************
  *****************************************************************************
  *****************************************************************************/
    // if port == 0, paket is coming from the lower layer
 
    if (p->length() < sizeof(struct click_wifi)) {
      p->kill();
      return;
    }

    uint8_t type;
    uint8_t subtype;

    struct click_wifi *w = (struct click_wifi *) p->data();

    EtherAddress src = EtherAddress(w->i_addr2);

    // Update Rx statistics
    update_rx_stats(p);
    
    // Stats_to_file
    if (_capture_mode == 1 && (( src == _capture_mac ) || (_capture_mac_str.equals("FF:FF:FF:FF:FF:FF")))) {
        stats_to_file(p,"mon0power.txt");
    }

    type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
    subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

    if (type == WIFI_FC0_TYPE_MGT) {

      // This is a management frame, now
      // we classify by subtype
      switch (subtype) {
        case WIFI_FC0_SUBTYPE_PROBE_REQ:
          {
            recv_probe_request (p);
            return;
          }
        case WIFI_FC0_SUBTYPE_ASSOC_REQ:
          {
            recv_assoc_request (p);
            return;
          }
        case WIFI_FC0_SUBTYPE_AUTH:
          {
            recv_open_auth_request (p);
            return;
          }
          case WIFI_FC0_SUBTYPE_DEAUTH:
          {
             recv_deauth (p);
             return;
          }
        default:
          {
            // Discard packet because we don't
            // need to handle other management
            // frame types for now.
            // FIXME: Need to handle DISSASOC
            p->kill ();
            return;
          }
      }
    }
    else if (type == WIFI_FC0_TYPE_DATA) {

      // This is a data frame, so we merely
      // filter against the VAPs.
      if (_sta_mapping_table.find (src) == _sta_mapping_table.end()) {
        // FIXME: Inform controller accordingly? We'll need this
        // for roaming.

        p->kill ();
        return;
      }

    // Get the destination address
    EtherAddress dst = EtherAddress(w->i_addr3);

      // if the destination address is a known LVAP
      if (_sta_mapping_table.find (dst) != _sta_mapping_table.end()) {

        // Destination station is a Odin client
        WritablePacket *p_out = 0;  // make the packet writable, to be sent to the network
        p_out = p->uniqueify();
    if (!p_out) {
            return;
        }
    
    // Wifi encapsulation
    struct click_wifi *w_out = (struct click_wifi *) p_out->data();
    memset(p_out->data(), 0, sizeof(click_wifi));
    w_out->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
    w_out->i_fc[1] = 0;
    w_out->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & WIFI_FC1_DIR_FROMDS);
      
    // modify the MAC address fields of the Wi-Fi frame
    OdinStationState oss = _sta_mapping_table.get (dst);
    memcpy(w_out->i_addr1, dst.data(), 6);
    memcpy(w_out->i_addr2, oss._vap_bssid.data(), 6);
    memcpy(w_out->i_addr3, src.data(), 6);

    // Update Tx statistics with this packet
    update_tx_stats(p_out);

    // send the frame by the output number 2
    output(2).push(p_out);
    return;
      }

      // There should be a WifiDecap element upstream.
      output(1).push(p);
      return;
    }
  /****************************************************************************
  *****************************************************************************
  *****************************************************************************
  *****************************************************************************/
  }
  else if (port == 1) {
  /****************************************************************************
  *****************************************************************************
  *****************************************************************************
  *****************************************************************************/
    // This means that the packet is coming from the higher layer,
    // so we simply filter by VAP and push out with the appropriate
    // bssid and wifi-encapsulation.
    const click_ether *e = (const click_ether *) (p->data() + 0 /*offset*/);
    const unsigned char *daddr = (const unsigned char *)e->ether_dhost;

    EtherAddress eth (daddr);

    // FIXME: We can avoid two lookups here
    if (_sta_mapping_table.find (eth) != _sta_mapping_table.end ())
    {
      OdinStationState oss = _sta_mapping_table.get (eth);
      
    // Add wifi header
      Packet *p_out = wifi_encap (p, oss._vap_bssid);
      // Update Tx statistics with this packet
      update_tx_stats(p_out);
      output(2).push(p_out);
      return;
    }
  }
  /****************************************************************************
  *****************************************************************************
  *****************************************************************************
  *****************************************************************************/
  else if (port == 2) { // if port == 2, packet is coming from the lower layer (from scanning device)
      
    if (p->length() < sizeof(struct click_wifi)) {
      p->kill();
      return;
    }  
    struct click_wifi *w = (struct click_wifi *) p->data();

    EtherAddress src = EtherAddress(w->i_addr2);
    // Stats_to_file
    if (_capture_mode == 1 && (( src == _capture_mac ) || (_capture_mac_str.equals("FF:FF:FF:FF:FF:FF")))) {
        stats_to_file(p,"mon1power.txt");
    }  
    if (_active_client_scanning == 1) {

      //fprintf(stderr, "[Odinagent.cc] ########### Scanning packets: Scanning activated \n");
      if (p->length() < sizeof(struct click_wifi)) {
        //fprintf(stderr, "[Odinagent.cc] ########### Scanning packets: Scanning activated --> killing packet \n");
        p->kill();
        return;
      }

      struct click_wifi *w = (struct click_wifi *) p->data();
      EtherAddress src = EtherAddress(w->i_addr2);
      if (src == _scanned_sta_mac) {
        if (_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc] ########### Scanning packets: Scanning activated --> found packet for  %s\n", src.unparse_colon().c_str());
              
        // Get station statistics
        struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
        _client_signal = ceh->rssi-256;
        _client_signal_mW = pow (10, _client_signal / 10); // Lineal power
        _client_avg_signal_mW = _client_avg_signal_mW  + ((_client_signal_mW  - _client_avg_signal_mW)/( _client_scanned_packets +1)); // Cumulative moving average
        _client_scanned_packets++; // New packet
        _client_avg_signal = 10.0*log10(_client_avg_signal_mW); // Lineal average power
        _client_scanning_result = (int) round(_client_avg_signal) + 256 + _signal_offset; // Result
        
        if (_debug_level % 10 > 1){
          fprintf(stderr, "[Odinagent.cc] ########### Packet number: %d\n",_client_scanned_packets);
          fprintf(stderr, "[Odinagent.cc] ########### Signal(mW): %f - Signal(dBm): %f\n",_client_signal_mW, _client_signal);
          fprintf(stderr, "[Odinagent.cc] ########### Average Signal(mW): %f - Average Signal(dBm): %f\n",_client_avg_signal_mW,_client_avg_signal);
        }
      }
      //fprintf(stderr, "[Odinagent.cc] ########### Scanning packets: Last power seen: --> %i\n", _client_scanning_result); // For testing
    }

    if (_active_AP_scanning == 1) {

      if (p->length() < sizeof(struct click_wifi)) {
        p->kill();
        return;
      }
    
      // I am only scanning certain SSID (e.g. "measurement beacons" have a special SSID)
      if (_scanning_SSID != "*") {

        struct click_wifi *w = (struct click_wifi *) p->data();
        type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
        subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

        if ((type == WIFI_FC0_TYPE_MGT) && (subtype == WIFI_FC0_SUBTYPE_BEACON)) {
          // obtain the SSID of this beacon
          String ssid = recv_beacon (p);

          // check if this SSID is the one I am looking for
          if (_scanning_SSID == ssid) {
            // the SSID of this frame is the one I am looking for
            // take all the information and store it  
            APScanning APscan;
            struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
            double signal_mW;
            double avg_signal_mW;
            int i = 0;
          
            // check if the MAC of this AP is already in the list
            for (Vector<OdinAgent::APScanning>::const_iterator iter = _APScanning_list.begin();
              iter != _APScanning_list.end(); iter++)
            {
              APscan = *iter;
              ++i;
              if (APscan.bssid == EtherAddress(w->i_addr2)) {
                // I have found a register with the MAC address of this frame
                // update the register
                APscan.packets++; // number of packets
                _APScanning_list.at(i-1).packets = APscan.packets; // update # packets
                signal_mW = pow (10, (ceh->rssi + _signal_offset - 256) / 10);
                avg_signal_mW  = pow (10, APscan.avg_signal / 10);
                avg_signal_mW = avg_signal_mW + ((signal_mW - avg_signal_mW)/APscan.packets);
                APscan.avg_signal = 10*log10 (avg_signal_mW); // signal in dBm  
                _APScanning_list.at(i-1).avg_signal = APscan.avg_signal; // update average signal
                p->kill();
                return;
              }
            }

            // the MAC is NOT in the list. I have to add a new register in '_APScanning_list'   
            //Add 
            APscan = APScanning();
            APscan.bssid = EtherAddress(w->i_addr2);
            APscan.packets++; // number of packets
            signal_mW = pow (10, (ceh->rssi + _signal_offset - 256) / 10);
            avg_signal_mW  = pow (10, APscan.avg_signal / 10);
            avg_signal_mW = avg_signal_mW + ((signal_mW - avg_signal_mW)/APscan.packets);
            APscan.avg_signal = 10*log10 (avg_signal_mW); // signal in dBm    
            _APScanning_list.push_back (APscan);  // add this record to _APScanning_list
          }
        }
      }
      else update_scanned_station_stats(p); // Scanning for every SSID. Update statistics of scanned stations
    }    
  }
  
  p->kill();
  return;
}

void
OdinAgent::add_subscription (long subscription_id, EtherAddress addr, String statistic, relation_t r, double val)
{
  Subscription sub;
  sub.subscription_id = subscription_id;
  sub.sta_addr = addr;
  sub.statistic = statistic;
  sub.rel = r;
  sub.val = val;
  sub.last_publish_sent= Timestamp::now(); //this stores the last timestamp when a Publish was sent
  _subscription_list.push_back (sub);

  if (_debug_level % 10 > 0)
   fprintf(stderr, "[Odinagent.cc] Subscription added\n");

}

void
OdinAgent::clear_subscriptions ()
{
  _subscription_list.clear();
  if (!_station_subs_table.empty())
    _station_subs_table.clear();  //clear time table
  if (_debug_level % 10 > 0)
    fprintf(stderr, "[Odinagent.cc] Subscriptions cleared\n");

}

void
OdinAgent::match_against_subscriptions(StationStats stats, EtherAddress src)
{
  if(_subscription_list.size() == 0)
    return;

    if (_multichannel_agents == 1) {
       // if the MAC is not in the mapping table, end the function
     if (_sta_mapping_table.find (src) == _sta_mapping_table.end()) 
          return;
     if (_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc] MAC %s is in the mapping table\n",src.unparse_colon().c_str());
  }

  Timestamp now = Timestamp::now();
  Timestamp age;
  int count = 0;
  int i = 0; 
  int matched = 0;
  
  StringAccum subscription_matches_prev;
  StringAccum subscription_matches;

  for (Vector<OdinAgent::Subscription>::const_iterator iter = _subscription_list.begin();
           iter != _subscription_list.end(); iter++) {

    Subscription sub = *iter;
  i++;
  subscription_matches_prev.clear();

  // EtherAddress builds a 00:00:00:00:00:00 MAC address (this is for dealing with '*' subscriptions)
  // First I check if the address of the arrived packet matches
  if (sub.sta_addr != EtherAddress() && sub.sta_addr != src)
    continue;

  if (_debug_level % 10 > 1)
    fprintf(stderr, "[Odinagent.cc]  MAC %s in subscription list\n",sub.sta_addr.unparse_colon().c_str());

    /* TODO: Refactor to use a series of hash maps instead */
    switch (sub.rel) {
      case EQUALS: {
        if (sub.statistic == "signal" && stats._signal == sub.val) {
          subscription_matches_prev << " " << sub.subscription_id << ":" << stats._signal; 
      matched = 1;
        } else if (sub.statistic == "rate" && stats._rate == sub.val) {
          subscription_matches_prev << " " <<  sub.subscription_id << ":" << stats._rate;
      matched = 1;
        } else if (sub.statistic == "noise" && stats._noise == sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._noise;
      matched = 1;
        } else if (sub.statistic == "_packets" && stats._packets == sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._packets;
      matched = 1;
        }
        break;
      }
      case GREATER_THAN: {
       if (sub.statistic == "signal" && stats._signal > sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._signal;
      matched = 1;
        } else if (sub.statistic == "rate" && stats._rate > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._rate;
      matched = 1;
        } else if (sub.statistic == "noise" && stats._noise > sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._noise;
      matched = 1;
        } else if (sub.statistic == "_packets" && stats._packets > sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._packets;
      matched = 1;
        }
        break;
      }
      case LESSER_THAN: {
        if (sub.statistic == "signal" && stats._signal < sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._signal;
      matched = 1;
        } else if (sub.statistic == "rate" && stats._rate < sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._rate;
      matched = 1;
        } else if (sub.statistic == "noise" && stats._noise < sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._noise;
      matched = 1;
        } else if (sub.statistic == "_packets" && stats._packets < sub.val) {
          subscription_matches_prev <<  " " << sub.subscription_id << ":" << stats._packets;
      matched = 1;
        }
        break;
      }
    }

  if (matched) { 
      if (sub.sta_addr != EtherAddress()) {
      // It is a specific subscription for a single MAC (not '*')
          // Calculate the time since the last publish was sent
        if (_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc]  It is a specific subscription for a single MAC (%s)\n",sub.sta_addr.unparse_colon().c_str());
        age = now - sub.last_publish_sent;
        if (_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc]  Age: %s   Now: %s   last_publish_sent: %s\n",age.unparse().c_str(),now.unparse().c_str(), sub.last_publish_sent.unparse().c_str());

        // age.sec is an integer with the number of seconds
        // age.usec is an integer with the number of microseconds
        if (_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc]  Age: %i Threshold: %i\n", ((age.sec() * 1000000 ) + age.usec()), THRESHOLD_PUBLISH_SENT);

        if (((age.sec() * 1000000 ) + age.usec() ) < THRESHOLD_PUBLISH_SENT)
          continue; // do not send the publish message to the controller

        _subscription_list.at(i-1).last_publish_sent = now; // update the timestamp
        ++count;
        subscription_matches << subscription_matches_prev.take_string();
        if (_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc]  Update timestamp for subscription:  src: %s   timestamp: %s\n",sub.sta_addr.unparse_colon().c_str(), _subscription_list.at(i-1).last_publish_sent.unparse().c_str());
      }

      else { 
      // it is a '*' subscription:
        // check the table with pairs of 'src' and timestamps
          if (_debug_level % 10 > 1)
            fprintf(stderr, "[Odinagent.cc]  It is a '*' subscription MAC (%s)\n",EtherAddress().unparse_colon().c_str());
          if(_station_subs_table.find(src) != _station_subs_table.end()){
            // the src is already in the table
             age = now - _station_subs_table.get (src);
             if (_debug_level % 10 > 1)
               fprintf(stderr, "[Odinagent.cc]  Age: %s   Now: %s   last_publish_sent: %s\n",age.unparse().c_str(),now.unparse().c_str(), _station_subs_table.get(src).unparse().c_str());

            // age.sec is an integer with the number of seconds
            // age.usec is an integer with the number of microseconds
            if (_debug_level % 10 > 1)
              fprintf(stderr, "[Odinagent.cc]  Age: %i Threshold: %i\n", ((age.sec() * 1000000 ) + age.usec()), THRESHOLD_PUBLISH_SENT);

            if (((age.sec() * 1000000 ) + age.usec() ) < THRESHOLD_PUBLISH_SENT)
              continue; // do not send the publish message to the controller
           }
           // I add a new register in the table or/and update it if exists
           _station_subs_table.set (src, now);
           ++count;
           subscription_matches << subscription_matches_prev.take_string();
           if (_debug_level % 10 > 1)
             fprintf(stderr, "[Odinagent.cc]  Add/Update register _station_subs_table  src: %s   timestamp: %s\n", src.unparse_colon().c_str(), _station_subs_table.get(src).unparse().c_str());
         } 
      matched = 0;

    }
  }
  if (count > 0) { // if there are no matches, do not send anything to the controller

  StringAccum sa;
  
  sa << "publish " << src.unparse_colon().c_str() << " " << count << subscription_matches.take_string() << "\n";
  
  String payload = sa.take_string();
  if (_debug_level % 10 > 1)
    fprintf(stderr, "[Odinagent.cc]  Publish sent %s\n",payload.c_str());
  WritablePacket *odin_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
  output(3).push(odin_probe_packet);
  }
}


/*
 * We have include new handlers an modified others
 *
 * @author Luis Sequeira <sequeira@unizar.es>
 *
 * */
String
OdinAgent::read_handler(Element *e, void *user_data)
{
  OdinAgent *agent = (OdinAgent *) e;
  StringAccum sa;

  switch (reinterpret_cast<uintptr_t>(user_data)) {

    // read handler mapping table
    case handler_view_mapping_table: {
      for (HashTable<EtherAddress, OdinStationState>::iterator it
          = agent->_sta_mapping_table.begin(); it.live(); it++)
        {
          sa << it.key().unparse_colon()
            << " " << it.value()._sta_ip_addr_v4
            <<  " " << it.value()._vap_bssid.unparse_colon();

          for (int i = 0; i < it.value()._vap_ssids.size(); i++) {
            sa << " " << it.value()._vap_ssids[i];
          }

          sa << "\n";
        }
      break;
    }

    // read handler channel
    case handler_channel: {
      sa << agent->_channel << "\n";
      break;
    }

    // read handler interval
    case handler_interval: {
      sa << agent->_interval_ms << "\n";
      break;
    }

    // read handler for transmission statistics
    case handler_txstat: {

    OdinAgent::StationStats reset_stats = OdinAgent::StationStats();
    Timestamp stats_time;

      // the controller will get the tx statistics of all the STAs associated to this AP
      //TODO: we could perhaps add another handler (write) which gets the statistics of a single MAC
    for (HashTable<EtherAddress, StationStats>::const_iterator iter = agent->_tx_stats.begin();
          iter.live(); iter++) {

      OdinAgent::StationStats n = iter.value();
    
      sa << iter.key().unparse_colon();
        
      sa << " packets:" << n._packets;
      sa << " avg_rate:" << n._avg_rate; // rate in Kbps
      sa << " avg_signal:" << n._avg_signal; // signal in dBm
      sa << " avg_len_pkt:" << n._avg_len_pkt; // length in bytes
      sa << " air_time:" << n._air_time; // time in seconds

      sa << " first_received:" << n._time_first_packet; // time in long format
      sa << " last_received:" << n._time_last_packet; // time in long format
            
            sa << " equipment:" << n._equipment << "\n"; // type of equipment
    
      stats_time = n._time_last_packet;
      agent->_tx_stats.find(iter.key()).value() = reset_stats;
      agent->_tx_stats.find(iter.key()).value()._time_first_packet = stats_time;
      agent->_tx_stats.find(iter.key()).value()._time_last_packet = stats_time;
    }  
      
    break;
    }

    // read handler for reception statistics
    case handler_rxstat: {

      OdinAgent::StationStats reset_stats = OdinAgent::StationStats();
      Timestamp stats_time;

      // the controller will get the rx statistics of all the STAs associated to this AP
      //TODO: we could perhaps add another handler (write) which gets the statistics of a single MAC
      for (HashTable<EtherAddress, StationStats>::const_iterator iter = agent->_rx_stats.begin();
          iter.live(); iter++) {

      OdinAgent::StationStats n = iter.value();

      sa << iter.key().unparse_colon();
        
      sa << " packets:" << n._packets;
      sa << " avg_rate:" << n._avg_rate; // rate in Kbps
      sa << " avg_signal:" << n._avg_signal; // signal in dBm
      sa << " avg_len_pkt:" << n._avg_len_pkt; // length in bytes
      sa << " air_time:" << n._air_time; // time in seconds

      sa << " first_received:" << n._time_first_packet; // time in long format
      sa << " last_received:" << n._time_last_packet; // time in long format
            
            sa << " equipment:" << n._equipment << "\n"; // type of equipment

      stats_time = n._time_last_packet;
      agent->_rx_stats.find(iter.key()).value() = reset_stats;
      agent->_rx_stats.find(iter.key()).value()._time_first_packet = stats_time;
      agent->_rx_stats.find(iter.key()).value()._time_last_packet = stats_time;
    }      

    break;
    }

    // read handler subscriptions
    case handler_subscriptions: {

      for (Vector<OdinAgent::Subscription>::const_iterator iter = agent->_subscription_list.begin();
           iter != agent->_subscription_list.end(); iter++) {

        OdinAgent::Subscription sub = *iter;
        sa << "sub_id " << sub.subscription_id;
        sa << " addr " << sub.sta_addr.unparse_colon();
        sa << " stat " << sub.statistic;
        sa << " rel " << sub.rel;
        sa << " val " << sub.val;
        sa << "\n";
      }

      break;
    }

    // read handler debug
    case handler_debug: {
      sa << agent->_debug_level << "\n";
      break;
    }

    // read handler report mean
    case handler_report_mean: {
      double variance = agent->_m2 / (agent->_num_mean -1);
      sa << agent->_mean <<  " " <<  agent->_num_mean << " " << variance << "\n";
      break;
    }
    
    // read handler scan clien
    case handler_scan_client: {
    // Disable scanning
      agent->_active_client_scanning = 0;
    // Scanning result
      sa << agent->_client_scanning_result << "\n"; 
    if (agent->_debug_level % 10 > 0)
      fprintf(stderr, "[Odinagent.cc] ########### Scanning: Sending STA scan results: %i (%i dBm)\n", agent->_client_scanning_result, (agent->_client_scanning_result)-256);
    if ( agent->_debug_level / 10 == 1)    // demo mode. I print more visual information
     fprintf(stderr, "##################################################################\n\n");
      break;
    }

    // read handler scan_APs
    case handler_scan_APs: {
      // Disable scanning
      agent->_active_AP_scanning = 0;
      // Scanning result
      if (agent->_scanning_SSID =="*"){
        // the controller will get the rx statistics of all the scanned STAs
        //TODO: we could perhaps add another handler (write) which gets the statistics of a single MAC
        for (HashTable<EtherAddress, StationStats>::const_iterator iter = agent->_scanned_station_stats.begin();
          iter.live(); iter++) {

        OdinAgent::StationStats n = iter.value();

        sa << iter.key().unparse_colon();
        
        sa << " packets:" << n._packets;
        sa << " avg_rate:" << n._avg_rate; // rate in Kbps
        sa << " avg_signal:" << n._avg_signal; // signal in dBm
        sa << " avg_len_pkt:" << n._avg_len_pkt; // length in bytes
        sa << " air_time:" << n._air_time; // time in seconds
        sa << " first_received:" << n._time_first_packet; // time in long format
        sa << " last_received:" << n._time_last_packet; // time in long format           
        sa << " equipment:" << n._equipment << "\n"; // type of equipment
      }
    }
    else {
      // the controller is scanning for a specific SSID
       for (Vector<OdinAgent::APScanning>::const_iterator iter = agent->_APScanning_list.begin();
           iter != agent->_APScanning_list.end(); iter++) {      
            OdinAgent::APScanning APscan = *iter;
            sa << APscan.bssid.unparse_colon();
            sa << " avg_signal:" << APscan.avg_signal << "\n"; // signal in dBm
       } 
        }
   
   if (agent->_debug_level % 10 > 0)
            fprintf(stderr, "[Odinagent.cc] ########### Scanning: Sending AP scanning values \n");
     break;
    }

    // read handler scanning_flags
    case handler_scanning_flags: { 
    sa << agent->_active_client_scanning << " " << agent->_active_AP_scanning << " " << agent->_active_measurement_beacon << "\n";;
    if (agent->_debug_level % 10 > 0)
    fprintf(stderr, "[Odinagent.cc] ########### Read scanning flags --> ClientScanningFlag: %i   APScanningFlag: %i    measurementBeaconFlag: %i\n", agent->_active_client_scanning, agent->_active_AP_scanning, agent->_active_measurement_beacon);
      break;
    }
    case handler_txpower: {
      sa << agent->_tx_power << "\n";
      break;
    }

    // read handler sta_rssi
    case handler_sta_rssi: {
    // Disable scanning
     agent->_active_AP_scanning = 0;
     // Scanning result
     for (HashTable<EtherAddress, StationStats>::const_iterator iter = agent->_scanned_station_stats.begin();iter.live(); iter++) {
      OdinAgent::StationStats n = iter.value();
      if(n._equipment=="STA"){
       sa << iter.key().unparse_colon();
       double rssi = floor(n._avg_signal*100 + 0.5)/100;
       sa << " " << rssi << "\n"; // signal in dBm
      }
     }

   if (agent->_debug_level % 10 > 0)
            fprintf(stderr, "[Odinagent.cc] ########### Scanning: Sending AP scanning values \n");
     break;
    }
  }

  return sa.take_string();
}

/*
 * We have include new handlers an modified others
 * 
 * @author Luis Sequeira <sequeira@unizar.es>
 * 
 * */

int
OdinAgent::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{

  OdinAgent *agent = (OdinAgent *) e;

  switch (reinterpret_cast<uintptr_t>(user_data)) {
    case handler_add_vap:{
      IPAddress sta_ip;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;

      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("STA_IP", sta_ip)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }

      if (agent->add_vap (sta_mac, sta_ip, vap_bssid, ssidList) < 0)
        {
          return -1;
        }
      break;
    }
    case handler_set_vap:{
      IPAddress sta_ip;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;

      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("STA_IP", sta_ip)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }

      if (agent->set_vap (sta_mac, sta_ip, vap_bssid, ssidList) < 0)
        {
          return -1;
        }
      break;
    }
    case handler_remove_vap:{
      EtherAddress sta_mac;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("STA_MAC", sta_mac)
        .complete() < 0)
        {
          return -1;
        }

      if (agent->remove_vap(sta_mac) < 0)
        {
          return -1;
        }
      break;
    }
    case handler_channel: { 
      int channel;
      int frequency;
      StringAccum sa;
      EtherAddress sta_mac; // From _sta_mapping_table
      EtherAddress vap_bssid; // From _sta_mapping_table
      
      if (Args(agent, errh).push_back_words(str)
        .read_mp("CHANNEL", channel)
        .complete() < 0)
        {
          return -1;
        }
      frequency = agent->convert_channel_to_frequency(channel);
      if (agent->_channel != channel) { //FIXME Two options, no STAs or yes, we have to warn them about channel switching
          
          if(agent->_sta_mapping_table.size() != 0) { // There is one or more STA in the AP
            agent->_new_channel = channel;
            if (agent->_debug_level % 10 > 0)
              fprintf(stderr, "[Odinagent.cc] #################### Setting csa and new channel %i\n", channel);
            
            for (HashTable<EtherAddress, OdinStationState>::iterator it
              = agent->_sta_mapping_table.begin(); it.live(); it++) // Loop for add CSA to all STA
            {
                agent->_csa_table.set(it.key(), agent->_count_csa_beacon_default); // Initialize CSA for that STA
            }
            
            for (int i = agent->_count_csa_beacon_default; i >= 0; i--){// Sending the CSA n times
              for (HashTable<EtherAddress, OdinStationState>::iterator it
                = agent->_sta_mapping_table.begin(); it.live(); it++) // Loop for sending CSAs to all STA
              {
                // assign ssidList from _sta_mapping_table
                Vector<String> ssidList;
                ssidList = it.value()._vap_ssids;
                for (Vector<String>::const_iterator it_ssid = ssidList.begin();
                  it_ssid != ssidList.end(); it_ssid++) {
                  agent->send_beacon (it.key(), it.value()._vap_bssid, *it_ssid, false);
                }
              }          
            }
          }
          
          sa << "hostapd_cli -i wlan0 chan_switch " << agent->_count_csa_beacon_default << " " << frequency << " > /dev/null";
          agent->_channel = channel;
          if (agent->_debug_level % 10 > 0)
            fprintf(stderr, "[Odinagent.cc] ########### Changing AP to channel %i\n", channel);
          system(sa.c_str()); // Set channel in wlan0
          // Send beacons for help after change of channel
          for (int j = 1; j <= agent->_burst_after_addlvap; j++) { // Burst after channel change
              for (HashTable<EtherAddress, OdinStationState>::iterator it
                = agent->_sta_mapping_table.begin(); it.live(); it++)
              {
                // assign ssidList from _sta_mapping_table
                Vector<String> ssidList;
                ssidList = it.value()._vap_ssids;
                for (Vector<String>::const_iterator it_ssid = ssidList.begin();
                  it_ssid != ssidList.end(); it_ssid++) {
                  agent->send_beacon (it.key(), it.value()._vap_bssid, *it_ssid, true);
                }
              } 
          }
      }else{
        if (agent->_debug_level % 10 > 0)
          fprintf(stderr, "[Odinagent.cc] ########### AP already in channel %i\n", channel);
      }
      break;
    }
    case handler_interval: {
      int interval;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("INTERVAL", interval)
        .complete() < 0)
        {
          return -1;
        }

      agent->_interval_ms = interval;
      break;
    }
    case handler_subscriptions: {
      /* Clear out subscriptions first */
      agent->clear_subscriptions();

      int num_rows;
      Args args(agent, errh);
      if (args.push_back_words(str)
        .read_mp("NUM_ROWS", num_rows)
        .consume() < 0)
        {
          return -1;
        }

      if (agent->_debug_level % 10 > 1)
        fprintf(stderr, "[Odinagent.cc] num_rows: %d\n", num_rows);

      for (int i = 0; i < num_rows; i++) {
        long sub_id;
        EtherAddress sta_addr;
        String statistic;
        int relation;
        double value;
        if (args
            .read_mp("sub_id", sub_id)
            .read_mp("addr", sta_addr)
            .read_mp("stat", statistic)
            .read_mp("rel", relation)
            .read_mp("val", value)
            .consume() < 0)
          {
            return -1;
          }

        agent->add_subscription (sub_id, sta_addr, statistic, static_cast<relation_t>(relation), value);
         if (agent->_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc] Subscription: %ld %s %s %i %f\n", sub_id, sta_addr.unparse_colon().c_str(), statistic.c_str(), relation, value);

      }

      if (args.complete() < 0) {
        return -1;
      }
      break;
    }
    case handler_debug: {
      bool debug;
      if (!BoolArg().parse(str, debug))
        return -1;

      agent->_debug_level = debug;
      break;
    }
    case handler_probe_response: {

      EtherAddress sta_mac;
      EtherAddress vap_bssid;

      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }

      for (Vector<String>::const_iterator it = ssidList.begin();
            it != ssidList.end(); it++) {
        agent->send_beacon (sta_mac, vap_bssid, *it, true);
      }
      break;
    }
    case handler_probe_request: {
      EtherAddress sta_mac;
      String ssid = "";

      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("STA_MAC", sta_mac)
          .consume() < 0)
        {
          return -1;
        }

      if (!args.empty()) {
        if (args.read_mp("SSID", ssid)
              .consume() < 0)
          {
            return -1;
          }
      }
      StringAccum sa;
      sa << "probe " << sta_mac.unparse_colon().c_str() << " " << ssid << "\n";
      String payload = sa.take_string();

      agent->_mean_table.set (sta_mac, Timestamp::now());
      WritablePacket *odin_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
      agent->output(3).push(odin_probe_packet);
      break;
    }
    case handler_update_signal_strength: {
      EtherAddress sta_mac;
      int value;

      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("STA_MAC", sta_mac)
          .read_mp("VALUE", value)
          .consume() < 0)
        {
          return -1;
        }

      StationStats stat;
      HashTable<EtherAddress, StationStats>::const_iterator it = agent->_rx_stats.find(sta_mac);

      if (it == agent->_rx_stats.end())
        stat = StationStats();
      else
        stat = it.value();

      stat._signal = value;
      stat._packets++;
      stat._time_last_packet.assign_now();

      agent->match_against_subscriptions(stat, sta_mac);
      agent->_rx_stats.set (sta_mac, stat);

      break;
    }
    case handler_signal_strength_offset: {
      int value;
      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("VALUE", value)
          .consume() < 0)
        {
          return -1;
        }

      agent->_signal_offset = value;
      break;
    }
    case handler_channel_switch_announcement: { // New handler for CSA-Beacon
      int new_channel;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;

      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("VAP_BSSID", vap_bssid)
      .read_mp("CHANNEL", new_channel)
            .consume() < 0)
        {
          return -1;
        }

      if (agent->_debug_level % 10 > 0)
    fprintf(stderr, "[Odinagent.cc] #################### Setting csa and new channel %i\n", new_channel);      
      
      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }
      
      agent->_new_channel = new_channel;
      
      agent->_csa_table.set(sta_mac, agent->_count_csa_beacon_default); // Initialize CSA for that STA
      
      for (int i = agent->_count_csa_beacon_default; i >= 0; i--){// Sending the CSA n times
        //if (agent->_debug_level % 10 > 0)
            //fprintf(stderr,i,"\n");
        for (Vector<String>::const_iterator it = ssidList.begin();
            it != ssidList.end(); it++) {
          agent->send_beacon (sta_mac, vap_bssid, *it, false);
        }
      }
      
      break;
    }
    case handler_scan_client: { // need testing
      if (agent->_active_client_scanning == 1 || agent->_active_AP_scanning == 1 || agent->_active_measurement_beacon == 1) {
      break; //FIXME
    }
      EtherAddress sta_mac;
      int scan_channel;
      int frequency;
      StringAccum sa;
      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
          .read_mp("CHANNEL", scan_channel)
          .complete() < 0)
      {
        return -1;
      }
    
    if (agent->_debug_level / 10 == 1)    // demo mode. I print more visual information
           fprintf(stderr, "##################################################################\n");
    
      if (agent->_debug_level % 10 > 0)
        fprintf(stderr, "[Odinagent.cc] ########### Scanning for client %s\n", sta_mac.unparse_colon().c_str());
    // Set channel to scan
      frequency = agent->convert_channel_to_frequency(scan_channel);
      sa << "hostapd_cli -i wlan1 chan_switch 0 " << frequency << " > /dev/null";
      if (agent->_debug_level % 10 > 0)
      fprintf(stderr, "[Odinagent.cc] ########### Scanning for client: Testing command line --> %s\n", sa.c_str()); // for testing
      if (agent->_scan_channel != scan_channel) {
        agent->_scan_channel = scan_channel;
        system(sa.c_str()); // Set channel to scan in wlan1 (auxiliary)
        if (agent->_debug_level % 10 > 0)
        fprintf(stderr, "[Odinagent.cc] ########### Scanning for client: Setting channel to scan in auxiliary interface \n"); // for testing
      }
     agent->_client_scanning_result = 0;
      agent->_scanned_sta_mac = sta_mac;
    agent->_client_scanned_packets = 0;
        agent->_client_avg_signal_mW = 0;
      agent->_active_client_scanning = 1; // Enable scanning (FIXME: time to begin this action)
      if (agent->_debug_level % 10 > 0)
        fprintf(stderr, "[Odinagent.cc] ########### Scanning for client: Setting scanning --> true \n"); // for testing
      break;
    }

    // write handler scan_APs
    case handler_scan_APs: { 
      if (agent->_active_client_scanning == 1 || agent->_active_AP_scanning == 1 || agent->_active_measurement_beacon == 1) {
      break; //FIXME
    }
      String ssid;
      int scan_channel;
      int frequency;
      //int interval;
      StringAccum sa;
      if (Args(agent, errh).push_back_words(str)
          .read_mp("SSID", ssid)
          .read_mp("CHANNEL", scan_channel)
          //.read_mp("INTERVAL", interval)
          .complete() < 0)
      {
        return -1;
      }
      if (agent->_debug_level % 10 > 0)
        fprintf(stderr, "[Odinagent.cc] ########### Scanning for APs (SSID %s) in channel %d\n", ssid.c_str(),scan_channel);
      // Set channel to scan
      frequency = agent->convert_channel_to_frequency(scan_channel);
      sa << "hostapd_cli -i wlan1 chan_switch 0 " << frequency << " > /dev/null";
      if (agent->_debug_level % 10 > 0)
      fprintf(stderr, "[Odinagent.cc] ########### Scanning for APs: Testing command line --> %s\n", sa.c_str()); // for testing
      if (agent->_scan_channel != scan_channel) {
        agent->_scan_channel = scan_channel;
        system(sa.c_str()); // Set channel to scan in wlan1 (auxiliary)
        if (agent->_debug_level % 10 > 0)
        fprintf(stderr, "[Odinagent.cc] ########### Scanning for APs: Setting channel to scan in auxiliary interface \n"); // for testing
      }
   
      // Enable scanning (FIXME: time to begin this action)
      agent->_active_AP_scanning = 1;
      agent->_scanning_SSID = ssid;
      //agent->_AP_scanning_interval = interval;
      if (agent->_scanning_SSID =="*")
           agent->_scanned_station_stats.clear();
      else agent->_APScanning_list.clear();
        break;
    }

    // write handler send_measurement_beacon
    case handler_send_measurement_beacon: { // need testing
      if (agent->_active_client_scanning == 1 || agent->_active_AP_scanning == 1 || agent->_active_measurement_beacon == 1) {
      break; //FIXME
    }
    String ssid;
      int scan_channel;
    int frequency;
    //int interval;
    StringAccum sa;
      if (Args(agent, errh).push_back_words(str)
          .read_mp("SSID", ssid)
          .read_mp("CHANNEL", scan_channel)
         // .read_mp("INTERVAL", interval)
          .complete() < 0)
      {
        return -1;
      }
      if (agent->_debug_level % 10 > 0)
        fprintf(stderr, "[Odinagent.cc] ########### Send measurement beacon (SSID %s) in channel %d\n", ssid.c_str(),scan_channel);
      
    // Set channel to send
      frequency = agent->convert_channel_to_frequency(scan_channel);
      sa << "hostapd_cli -i wlan1 chan_switch 0 " << frequency << " > /dev/null";
      if (agent->_debug_level % 10 > 0)
      fprintf(stderr, "[Odinagent.cc] ########### Send measurement beacon: Testing command line --> %s\n", sa.c_str()); // for testing
      if (agent->_scan_channel != scan_channel) {
        agent->_scan_channel = scan_channel;
        system(sa.c_str()); // Set channel to scan in wlan1 (auxiliary)
        if (agent->_debug_level % 10 > 0)
        fprintf(stderr, "[Odinagent.cc] ########### Send measurement beacon: command line --> %s\n", sa.c_str()); // for testing
      }

      // Enable measurement beacon (FIXME: time to begin this action)
    agent->_active_measurement_beacon = 1;
    agent->_measurement_beacon_SSID = ssid; 
    //agent->_measurement_beacon_interval = interval;
    //agent->_num_measurement_beacon = 0;
      break;
    }

    // write handler flags
    case handler_scanning_flags: { 
      int client_scanning_flag;
      int AP_scanning_flag;
      int measurement_beacon_flag;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("ClientScanningFlag", client_scanning_flag)
        .read_mp("APScanningFlag", AP_scanning_flag)
        .read_mp("measurementBeaconFlag", measurement_beacon_flag)
        .complete() < 0)
        {
          return -1;
        }
     //Set scanning to do
      agent->_active_client_scanning = client_scanning_flag;
      agent->_active_AP_scanning = AP_scanning_flag;
      agent->_active_measurement_beacon = measurement_beacon_flag;
    if (agent->_debug_level % 10 > 0)
        fprintf(stderr, "[Odinagent.cc] ########### Changing scanning flags --> ClientScanningFlag:%i   APScanningFlag:%i    measurementBeaconFlag:%i\n", 
                         agent->_active_client_scanning, agent->_active_AP_scanning, agent->_active_measurement_beacon);
      break;
    }   
  }
  return 0;
}


void
OdinAgent::add_handlers()
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
  add_read_handler("scan_APs", read_handler, handler_scan_APs);
  add_read_handler("scanning_flags", read_handler, handler_scanning_flags);
  add_read_handler("txpower", read_handler, handler_txpower);
  add_read_handler("sta_rssi", read_handler, handler_sta_rssi);

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
  add_write_handler("scan_APs", write_handler, handler_scan_APs);
  add_write_handler("send_measurement_beacon", write_handler, handler_send_measurement_beacon);
  add_write_handler("scanning_flags", write_handler, handler_scanning_flags);

}

/* This debug function prints info about clients */
void
OdinAgent::print_stations_state()
{
  if (_debug_level % 10 > 0) {    // debug is activated
    if (_debug_level / 10 == 1)    // demo mode. I print more visual information, i.e. rows of "#'
      fprintf(stderr, "##################################################################\n");

    fprintf(stderr,"[Odinagent.cc] ##### Periodic report. Number of stations associated: %i\n", _sta_mapping_table.size());
    
    if(_sta_mapping_table.size() != 0) {

      // Initialize the statistics
      HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter_tx = _tx_stats.begin();
      HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter_rx = _rx_stats.begin();
      
      // For each VAP
      for (HashTable<EtherAddress, OdinStationState>::iterator it  = _sta_mapping_table.begin(); it.live(); it++) {

        // Each VAP may have a number of SSIDs
        //for (int i = 0; i < it.value()._vap_ssids.size (); i++) {
        
        // Print only if it has an valid IP
        if (it.value()._sta_ip_addr_v4.empty() == false) { 
          fprintf(stderr,"[Odinagent.cc]        Station -> BSSID: %s\n", (it.value()._vap_bssid).unparse_colon().c_str());
          fprintf(stderr,"[Odinagent.cc]                -> IP addr: %s\n", it.value()._sta_ip_addr_v4.unparse().c_str());
        }
        else {
          //fprintf(stderr,"[Odinagent.cc]        Station -> IP addr: 0.0.0.0\n" ); // for testing
          continue;
        }
        //}

        //stats
        //Print info from our stations if available
        HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter_tx = _tx_stats.find(it.key());
        if (iter_tx != _tx_stats.end()) { 
          fprintf(stderr,"[Odinagent.cc]          Downlink (transmission)\n");
          fprintf(stderr,"[Odinagent.cc]                -> last_packet_rate: %i (%i kbps)\n", iter_tx.value()._rate,iter_tx.value()._rate * 500 );
          fprintf(stderr,"[Odinagent.cc]                -> last_packet_noise: %i\n", (iter_tx.value()._noise));
          fprintf(stderr,"[Odinagent.cc]                -> last_packet_signal: %i (%i dBm)\n", iter_tx.value()._signal, iter_tx.value()._signal - 256 ); // value - 256)
          fprintf(stderr,"[Odinagent.cc]                -> last_packet_length: %i bytes\n", iter_tx.value()._len_pkt); 

          fprintf(stderr,"[Odinagent.cc]                -> total packets: %i\n", iter_tx.value()._packets);
          fprintf(stderr,"[Odinagent.cc]                -> avg_rate: %f Kbps\n", iter_tx.value()._avg_rate);
          fprintf(stderr,"[Odinagent.cc]                -> avg_signal: %f dBm\n", iter_tx.value()._avg_signal);
          fprintf(stderr,"[Odinagent.cc]                -> avg_len_pkt: %f bytes\n", iter_tx.value()._avg_len_pkt);
          fprintf(stderr,"[Odinagent.cc]                -> air_time: %f ms\n", iter_tx.value()._air_time);
          
          fprintf(stderr,"[Odinagent.cc]                -> first heard: %d.%06d sec\n", (iter_tx.value()._time_first_packet).sec(), (iter_tx.value()._time_first_packet).subsec());
          fprintf(stderr,"[Odinagent.cc]                -> last heard: %d.%06d sec\n", (iter_tx.value()._time_last_packet).sec(), (iter_tx.value()._time_last_packet).subsec());
          
          // Calculate the time between the two timestamps: the hearing interval in which the statistics have been calculated
          Timestamp interval_tx = iter_tx.value()._time_last_packet - iter_tx.value()._time_first_packet;
          fprintf(stderr,"[Odinagent.cc]                -> interval heard: %d.%06d sec\n", interval_tx.sec(), interval_tx.subsec());          
          fprintf(stderr,"[Odinagent.cc]\n");
        }

        HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter_rx = _rx_stats.find(it.key());
        if (iter_rx != _rx_stats.end()) { 
          fprintf(stderr,"[Odinagent.cc]          Uplink (reception)\n");
          fprintf(stderr,"[Odinagent.cc]                -> last_packet_rate: %i (%i kbps)\n", iter_rx.value()._rate,iter_rx.value()._rate * 500 );
          fprintf(stderr,"[Odinagent.cc]                -> last_packet_noise: %i\n", (iter_rx.value()._noise));
          fprintf(stderr,"[Odinagent.cc]                -> last_packet_signal: %i (%i dBm)\n", iter_rx.value()._signal, iter_rx.value()._signal - 256 ); // value - 256)
          fprintf(stderr,"[Odinagent.cc]                -> last_packet_length: %i bytes\n", iter_rx.value()._len_pkt); 

          fprintf(stderr,"[Odinagent.cc]                -> total packets: %i\n", iter_rx.value()._packets);
          fprintf(stderr,"[Odinagent.cc]                -> avg_rate: %f Kbps\n", iter_rx.value()._avg_rate);
          fprintf(stderr,"[Odinagent.cc]                -> avg_signal: %f dBm\n", iter_rx.value()._avg_signal);
          fprintf(stderr,"[Odinagent.cc]                -> avg_len_pkt: %f bytes\n", iter_rx.value()._avg_len_pkt);
          fprintf(stderr,"[Odinagent.cc]                -> air_time: %f ms\n", iter_rx.value()._air_time);
          
          fprintf(stderr,"[Odinagent.cc]                -> first heard: %d.%06d sec\n", (iter_rx.value()._time_first_packet).sec(), (iter_rx.value()._time_first_packet).subsec());
          fprintf(stderr,"[Odinagent.cc]                -> last heard: %d.%06d sec\n", (iter_rx.value()._time_last_packet).sec(), (iter_rx.value()._time_last_packet).subsec());

          // Calculate the time between the two timestamps: the hearing interval in which the statistics have been calculated
          Timestamp interval_rx = iter_rx.value()._time_last_packet - iter_rx.value()._time_first_packet;
          fprintf(stderr,"[Odinagent.cc]                -> interval heard: %d.%06d sec\n", interval_rx.sec(), interval_rx.subsec());
          
          fprintf(stderr,"[Odinagent.cc]\n");
        }
      }
    }      
    if (_debug_level / 10 == 1)    // demo mode. I print more visual information
        fprintf(stderr, "##################################################################\n\n");
  }
}


/* Thread for general purpose (i.e. print debug info about them)*/
void misc_thread(Timer *timer, void *data){

    OdinAgent *agent = (OdinAgent *) data;

    agent->print_stations_state();

    timer->reschedule_after_sec(RESCHEDULE_INTERVAL_GENERAL);

}


void
OdinAgent::send_measurement_beacon () {

  EtherAddress bssid = _hw_mac_addr;
  String my_ssid = _measurement_beacon_SSID;

  Vector<int> rates = _rtable->lookup(bssid);

  /* order elements by standard
   * needed by sloppy 802.11b driver implementations
   * to be able to connect to 802.11g APs */
  int max_len = sizeof (struct click_wifi) +
    8 +                  /* timestamp */
    2 +                  /* beacon interval */
    2 +                  /* cap_info */
    2 + my_ssid.length() + /* ssid */
    2 + WIFI_RATES_MAXSIZE +  /* rates */
    0;


  WritablePacket *p = Packet::make(max_len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT;
  w->i_fc[0] |=  WIFI_FC0_SUBTYPE_BEACON;
  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, "FF:FF:FF:FF:FF:FF", 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);

  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof (struct click_wifi);


  /* timestamp is set in the hal. ??? */
  memset(ptr, 0, 8);
  ptr += 8;
  actual_length += 8;

  /* beacon interval */
  uint16_t beacon_int = (uint16_t) _interval_ms_measurement_beacon;
  *(uint16_t *)ptr = cpu_to_le16(beacon_int);
  ptr += 2;
  actual_length += 2;

  // Capability information
  uint16_t cap_info = 0;
  cap_info |= WIFI_CAPINFO_ESS;
  *(uint16_t *)ptr = cpu_to_le16(cap_info);
  ptr += 2;
  actual_length += 2;

  /* ssid */
  ptr[0] = WIFI_ELEMID_SSID;
  ptr[1] = my_ssid.length();
  memcpy(ptr + 2, my_ssid.data(), my_ssid.length());
  ptr += 2 + my_ssid.length();
  actual_length += 2 + my_ssid.length();

  /* rates */
  ptr[0] = WIFI_ELEMID_RATES;
  ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
    ptr[2 + x] = (uint8_t) rates[x];

    if (rates[x] == 2) {
      ptr [2 + x] |= WIFI_RATE_BASIC;
    }

  }
  ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());


  p->take(max_len - actual_length);

  output(4).push(p);
}



/* Thread for mon1 scanning interface (AP scanning, send measurement beacon, ...) */
void scanning_thread(Timer *timer, void *data){

    OdinAgent *agent = (OdinAgent *) data;

  // measurement beacon
  if (agent->_active_measurement_beacon == 1) 
     agent->send_measurement_beacon ();

    /*if (agent->_active_measurement_beacon) {
    if ((agent->_num_intervals_for_measurement_beacon % (RESCHEDULE_INTERVAL_measurement_BEACON / RESCHEDULE_INTERVAL_SCANNING)) == 0) {
      agent->send_measurement_beacon ();
      ++(agent->_num_measurement_beacon);
        if (agent->_num_measurement_beacon > (agent->_measurement_beacon_interval/RESCHEDULE_INTERVAL_measurement_BEACON)) { 
        agent->_active_measurement_beacon = false; //When interval time had finished
        agent->_num_intervals_for_measurement_beacon = 1;
      }
    }
    if (agent->_active_measurement_beacon)
      ++agent->_num_intervals_for_measurement_beacon;
  }*/
  
  // AP Scanning
  /*if (agent->_active_AP_scanning) {
    if (agent->_AP_scanning_interval - (RESCHEDULE_INTERVAL_SCANNING*agent->_num_intervals_for_AP_scanning) < 0 ){
      agent->_active_AP_scanning = false;
      agent->_num_intervals_for_AP_scanning = 0;
    }

    if (agent->_active_AP_scanning)
      ++(agent->_num_intervals_for_AP_scanning);
  }*/

    timer->reschedule_after_msec(agent->_interval_ms_measurement_beacon);
}


/* This function erases old statistics from station not associated. It also erases old lvaps from inactive stations */
void
cleanup_lvap (Timer *timer, void *data)
{

    OdinAgent *agent = (OdinAgent *) data;
    Vector<EtherAddress> buf;


    for (HashTable<EtherAddress, OdinAgent::StationStats>::const_iterator iter = agent->_rx_stats.begin();
    iter.live(); iter++){

       // Clear out rxstat entries from station not associated
    if (agent->_sta_mapping_table.find(iter.key()) == agent->_sta_mapping_table.end()) {
      buf.push_back (iter.key());
      continue;
    }

        Timestamp now = Timestamp::now();
        Timestamp age = now - iter.value()._time_last_packet;
    
        //If out station has been inactive longer than the given threshold we remove the lvap and info at the master, then the stats will be removed too
        if(age.sec() > THRESHOLD_REMOVE_LVAP){

            // Notify the master to remove client info and lvap, then agent clears the lvap
            StringAccum sa;
            sa << "deauthentication " << iter.key().unparse_colon().c_str() << "\n";

            String payload = sa.take_string();
            WritablePacket *odin_disconnect_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
            agent->output(3).push(odin_disconnect_packet);

        }
    }

    if (agent->_debug_level % 10 > 0)
      fprintf(stderr,"\n[Odinagent.cc] Cleaning old info from stations not associated\n");

    for (Vector<EtherAddress>::const_iterator iter = buf.begin(); iter != buf.end(); iter++) {

        //If its our station we dont remove, we need the _time_last_packet to see if its inactive or not
        if(agent->_sta_mapping_table.find(*iter) != agent->_sta_mapping_table.end())
            continue;

    if (agent->_debug_level % 10 > 1)
          fprintf(stderr, "[Odinagent.cc]   station with MAC addr: %s\n", iter->unparse_colon().c_str());
        agent->_rx_stats.erase (*iter);
    agent->_tx_stats.erase (*iter);
    }

    //agent->_packet_buffer.clear();
    timer->reschedule_after_sec(RESCHEDULE_INTERVAL_STATS);
}


/*Miscellaneous*/
int
OdinAgent::convert_frequency_to__channel(int freq) {
    if (freq >= 2412 && freq <= 2484) {
        int chan = (freq - 2412) / 5 + 1;
        return chan;
    } else if (freq >= 5170 && freq <= 5825) {
        int chan = (freq - 5170) / 5 + 34;
        return chan;
    } else {
        return -1;
    }
}

int
OdinAgent::convert_channel_to_frequency(int chan) {
    if (chan >= 1 && chan <= 14) {
        int freq = 5 * (chan - 1) + 2412;
        return freq;
    } else if (chan >= 34 && chan <= 165) {
        int freq = 5 * (chan - 34) + 5170;
        return freq;
    } else {
        return -1;
    }
}


CLICK_ENDDECLS
EXPORT_ELEMENT(OdinAgent)
ELEMENT_REQUIRES(userlevel)
