/**********************************************
 * * Author: Zhibin Wu, WINLAB, Rutgers University
 * * Date  August 2003
 * *
 * **********************************************/


#ifndef cmu_FixRT_h_
#define cmu_FixRT_h_

#include "config.h"
#include "agent.h"
#include "ip.h"
#include "delay.h"
#include "scheduler.h"
#include "queue.h"
#include "trace.h"
#include "arp.h"
#include "ll.h"
#include "mac.h"
#include "priqueue.h"
#include "fixtb.h"
#include <classifier/classifier-port.h>

#if defined(WIN32) && !defined(snprintf)
#define snprintf _snprintf
#endif /* WIN32 && !snprintf */

typedef double Time;

#define NOW	Scheduler::instance().clock()
#define ROUTER_PORT      0xff

class FixRT_Agent : public Tap, public Agent {
 
public:
  FixRT_Agent();
  virtual int command(int argc, const char * const * argv);
  // DTSN additions
  int get_num_hops(nsaddr_t dst);
  int nonCaching(int node);
  int dtsn_cached_enabled_;
  void tap(const Packet *p);
  
protected:
 
  virtual void recv(Packet *, Handler *);
  void trace(char* fmt, ...);
  void tracepkt(Packet *, double, int, const char *);
  //void processUpdate (Packet * p);
  void forwardPacket (Packet * p);
  void startUp();
  void makeRoutingTable(char *fn);
  int diff_subnet(int dst);
  void sendOutBCastPkt(Packet *p);
    
  // update old_rte in routing table to to new_rte
  Trace *tracetarget;       // Trace Target
  FixRTable *table_;     // Routing Table
  PriQueue *ll_queue;       // link level output queue
  int myaddr_;              // My address...
  
  // Extensions for mixed type simulations using wired and wireless
  // nodes
  char *subnet_;            // My subnet
  MobileNode *node_;        // My node
  // for debugging
  char *address;
  NsObject *port_dmux_;    // my port dmux
  //PortClassifier *port_dmux_;

  //Event *periodic_callback_;           // notify for periodic update
  
  // Randomness/MAC/logging parameters
  
  int be_random_;
  int verbose_;
  
  void output_rte(const char *prefix, fixrt_ent *prte, FixRT_Agent *a);
  Mac *mac_;
  char tbuf[100];
  FILE *tFile;
  double out_info_rate_;
  double last_sent_;
};

#endif
