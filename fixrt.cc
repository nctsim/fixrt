/**********************************************
 * * Author: Zhibin Wu, WINLAB, Rutgers University
 * * Date  August 2003
 * *
 * **********************************************/

extern "C" {
#include <stdarg.h>
#include <float.h>
};

#include "fixrt.h"
#include "priqueue.h"

#include <random.h>
#include <cmu-trace.h>
#include <address.h>
#include <mobilenode.h>
#include <dtsn/dtsn-pkt.h>
#include <ndtsn/ndtsn.h>
#include <rmst/rmst.h>
#include <dtsncc/dtsncc.h>
#include <dtpa/dtpa.h>
#include <stat.h>
//#include <file.h>

#define ROUTE_FILE "routes"  //zhibinwu
#define ENABLE_DTSN
//#define DEBUGDTSN

#define FixRT_ALMOST_NOW     0.1 // jitter used for events that should be effectively
				// instantaneous but are jittered to prevent
				// synchronization
#define FixRT_BROADCAST_JITTER 0.01 // jitter for all broadcast packets

#define IP_DEF_TTL   32 // default TTTL

#undef TRIGGER_UPDATE_ON_FRESH_SEQNUM
//#define TRIGGER_UPDATE_ON_FRESH_SEQNUM
/* should the receipt of a fresh (newer) sequence number cause us
   to send a triggered update?  If undef'd, we'll only trigger on
   routing metric changes */

// Returns a random number between 0 and max

static inline double 
jitter (double max, int be_random_)
{
  return (be_random_ ? Random::uniform(max) : 0);
}

static int noncachingnodes[]={};
//static int noncachingnodes[]={1,2,3,5,10,15,21,22,23,9,14,19};
//static int noncachingnodes[]={10,20,30,40,50,60,70,80,1,2,3,4,5,6,7,8,19,29,39,49,59,69,79,89,91,92,93,94,95,96,97,98};

int 
FixRT_Agent::nonCaching(int node) {
	int i, found=0;
	
	for (i=0; i<sizeof(noncachingnodes); i++) {
		if (node==noncachingnodes[i]) {
			found=1;
			break;
		}
	}
	return found;
}
   
void
FixRT_Agent::makeRoutingTable(char *fn) {
        int src,dst,nexthop,hoplen;
        FILE *fp = fopen(fn,"r");
        if ( fp == NULL)printf("FIXRT: configure routing table file open failed!\n");
        while(fscanf(fp,"%d %d %d %d\n",&src,&dst,&nexthop,&hoplen)!=EOF) {
                if (myaddr_ != src) {
                        continue;
                } else {
                        fixrt_ent rte;
                        bzero(&rte, sizeof(rte));
                        rte.dst = dst;
                        rte.hop = nexthop;
                        rte.metric = hoplen;
                        //printf("update route being called initially for route from %d to %d.\n",src,dst);
                        table_->AddEntry (rte);
                }
        }
        fclose(fp);
}

void FixRT_Agent::
trace (char *fmt,...)
{
  va_list ap;

  if (!tracetarget)
    return;

  va_start (ap, fmt);
  vsprintf (tracetarget->pt_->buffer (), fmt, ap);
  tracetarget->pt_->dump ();
  va_end (ap);
}

void 
FixRT_Agent::tracepkt (Packet * p, double now, int me, const char *type)
{
  char buf[1024];

  unsigned char *walk = p->accessdata ();

  int ct = *(walk++);
  int seq, dst, met;

  snprintf (buf, 1024, "V%s %.5f _%d_ [%d]:", type, now, me, ct);
  while (ct--)
    {
      dst = *(walk++);
      dst = dst << 8 | *(walk++);
      dst = dst << 8 | *(walk++);
      dst = dst << 8 | *(walk++);
      met = *(walk++);
      seq = *(walk++);
      seq = seq << 8 | *(walk++);
      seq = seq << 8 | *(walk++);
      seq = seq << 8 | *(walk++);
      snprintf (buf, 1024, "%s (%d,%d,%d)", buf, dst, met, seq);
    }
  // Now do trigger handling.
  //trace("VTU %.5f %d", now, me);
  if (verbose_)
    trace ("%s", buf);
}

// Prints out an rtable element.
void
FixRT_Agent::output_rte(const char *prefix, fixrt_ent  * prte, FixRT_Agent * a)
{
  a->trace("DFU: deimplemented");
  printf("DFU: deimplemented");

  prte = 0;
  prefix = 0;
#if 0
  printf ("%s%d %d %d\n",
	  prefix, prte->dst, prte->hop, prte->metric);
  a->trace ("VTE %.5f %d %d %d",
          Scheduler::instance ().clock (), prte->dst, prte->hop, prte->metric,
	 );
#endif
}



static void 
mac_callback (Packet * p, void *arg)
{
 // ((FixRT_Agent *) arg)->lost_link (p);
}


int 
FixRT_Agent::diff_subnet(int dst) 
{
	char* dstnet = Address::instance().get_subnetaddr(dst);
	if (subnet_ != NULL) {
		if (dstnet != NULL) {
			if (strcmp(dstnet, subnet_) != 0) {
				delete [] dstnet;
				return 1;
			}
			delete [] dstnet;
		}
	}
	//assert(dstnet == NULL);
	return 0;
}



void
FixRT_Agent::forwardPacket (Packet * p)
{
  hdr_ip *iph = HDR_IP(p);
  Scheduler & s = Scheduler::instance ();
  double now = s.clock ();
  hdr_cmn *hdrc = HDR_CMN (p);
  int dst;
  fixrt_ent  *prte;
  hdr_ndtsn *th = HDR_NDTSN(p);
  double delta;
  
  // We should route it.
  //printf("(%d)-->forwardig pkt\n",myaddr_);
  // set direction of pkt to -1 , i.e downward
  hdrc->direction() = hdr_cmn::DOWN;

  // if the destination is outside mobilenode's domain
  // forward it to base_stn node
  // Note: pkt is not buffered if route to base_stn is unknown

  dst = Address::instance().get_nodeaddr(iph->daddr());  
  if (diff_subnet(iph->daddr())) {
	   prte = table_->GetEntry (dst);
	  //if (prte && prte->metric != BIG) 
	   if (prte)  goto send;
	  
	  //int dst = (node_->base_stn())->address();
	  dst = node_->base_stn();
	  prte = table_->GetEntry (dst);
	  if (prte) 
		  goto send;
	  
	  else {
		  //drop pkt with warning
		  fprintf(stderr, "warning: Route to base_stn not known: dropping pkt\n");
		  Packet::free(p);
		  return;
	  }
  }
  
  prte = table_->GetEntry (dst);
  
   if (prte)
    {
       //printf("(%d)-have route for dst\n",myaddr_);
       goto send;
    }
  else
    { // Brand new destination
      //this is impossible for fix routing, we are going to do nothing
      // with this kind of packet, and let it disappear here.
            return;
    }


 send:
  hdrc->addr_type_ = NS_AF_INET;
  hdrc->xmit_failure_ = mac_callback;
  hdrc->xmit_failure_data_ = this;
  if (prte->metric > 1)
	  hdrc->next_hop_ = prte->hop;
  else
	  hdrc->next_hop_ = dst;
  if (verbose_)
	  trace ("Routing pkts outside domain: \
VFP %.5f _%d_ %d:%d -> %d:%d", now, myaddr_, iph->saddr(),
		 iph->sport(), iph->daddr(), iph->dport());  

  assert (!HDR_CMN (p)->xmit_failure_ ||
	  HDR_CMN (p)->xmit_failure_ == mac_callback);
 
  if(tFile!=NULL && th->data()) fprintf(tFile, "%f FORWARDED \t%d \t%d \tsrc %d:%d \tdst %d:%d \tmac_seq:%d\n", NOW,  th->snum(), th->seqno(), iph->saddr(), iph->sport(), iph->daddr(), iph->dport(), hdrc->num_attempts);	

  if (th->data()) {
    if (last_sent_==0) {
	  delta = 0;
	  out_info_rate_ = 0;
	  }			
    else {
	  delta = NOW - last_sent_;
	  if (delta) out_info_rate_ = 1.0/delta;
	  else out_info_rate_ = 0;
	  }
    last_sent_ = NOW;

    if (tFile!=NULL) 
	  fprintf(tFile,"%f OUTRATE \t%d \t%d \t%f\n", NOW, th->snum(), th->seqno(), out_info_rate_);
  }  
  target_->recv(p, (Handler *)0);
  return;
  
}

void 
FixRT_Agent::sendOutBCastPkt(Packet *p)
{
  Scheduler & s = Scheduler::instance ();
  // send out bcast pkt with jitter to avoid sync
  s.schedule (target_, p, jitter(FixRT_BROADCAST_JITTER, be_random_));
}

int
FixRT_Agent::get_num_hops(nsaddr_t dst) {
	
	fixrt_ent  *prte;

	prte = table_->GetEntry (dst);
	if (prte) return (prte->metric);
	else return 0;
}

void
FixRT_Agent::recv (Packet * p, Handler *)
{
  hdr_ip *iph = HDR_IP(p);
  hdr_cmn *cmh = HDR_CMN(p);
  int src = Address::instance().get_nodeaddr(iph->saddr());
  int dst = cmh->next_hop();
 
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_dtsn *dtsnh = HDR_DTSN(p);
  struct hdr_ndtsn *th = HDR_NDTSN(p);
  struct hdr_rmst *rh = HDR_RMST(p);
  struct hdr_dtsncc *dth = HDR_DTSNCC(p);
  struct hdr_dtpa *dtpahdr = HDR_DTPA(p);
  int forward=1;

//#ifdef ENABLE_DTSN
/*
	hdr_dtsn* dtsnh = HDR_DTSN(p);
	if (ch->ptype() == PT_DTSN && dtsnh->flags.data==0x01 && dtsnh->flags.rst==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() == myaddr_ ) {
	rt_print(index);
	}
*/

/*
 * NDTSN
 */
if (ch->ptype() == PT_NDTSN && th->etx()==1 && ch->direction() == hdr_cmn::UP) {
		Packet *pkt;	
		pkt = allocpkt();
		pkt = p->copy();
		port_dmux_->recv(pkt, (Handler*)0);
}

if (ch->ptype() == PT_NDTSN && th->data()==0x01 && hdr_cmn::DOWN && th->saddr() == myaddr_ ) {
    th->hops_to_dst_ = get_num_hops(ih->daddr());
    th->hops_to_src_ = get_num_hops(ih->saddr());
    //printf("Source src:%d dst:%d hops:%d\n", ih->saddr(), ih->daddr(), th->hops_to_dst_ );
    }

if (ch->ptype() == PT_NDTSN && th->data()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_ndtsn *dtsnc = HDR_NDTSN(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3000;
	#ifdef DEBUGDTSN
	printf("DATA (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), th->seqno());
	#endif
	//if(tFile!=NULL) fprintf(tFile, "%f RECEIVED \t%d \t%d \t%d:%d \t%d:%d \t%d\n", NOW,  th->snum(), th->seqno(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), ch->num_attempts);
	dtsnc->hops_to_dst_ = get_num_hops(ih->daddr());
	dtsnc->hops_to_src_ = get_num_hops(ih->saddr());
	th->hops_to_dst_ = get_num_hops(ih->daddr());
	th->hops_to_src_ = get_num_hops(ih->saddr());
	if (dtsn_cached_enabled_) port_dmux_->recv(pkt, (Handler*)0);
	if (th->ear()) {
		//printf("Node %d EAR seqno: %d\n", addr(), dtsnh->seqno);
		forward=1;
		}
	}

if (ch->ptype() == PT_NDTSN && th->nack()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_ndtsn *dtsnc = HDR_NDTSN(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3000;
	#ifdef DEBUGDTSN
	printf("NACK (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), th->seqno());
	//showDtsnHeader(p, "AODV", addr());
	#endif
	dtsnc->hops_to_dst_ = get_num_hops(ih->daddr());
	dtsnc->hops_to_src_ = get_num_hops(ih->saddr());
	//printf ("%d to %d: %d hops %d\n", addr(), ih->daddr(), dtsnc->hops_to_dst, dtsnc->hops_to_src );
	//showDtsnHeader(pkt2, "NACK", addr());
	//printf("\n<AODV> NACK src:%d sport:%d dst:%d dport:%d", ih->saddr(), ih->sport(), ih->daddr(), ih->dport());
	//if (dtsn_cached_enabled_ && !nonCaching(addr()))
	if (dtsn_cached_enabled_) port_dmux_->recv(pkt, (Handler*)0);
	//FILE *fp;
	//fp = fopen("ack.txt", "r");
	//fscanf(fp, "%04x %04x %04x\n", &dtsnh->NACKbitmap, &dtsnh->flags.ack, &dtsnh->flags.nack);
	//fclose(fp);
	forward = 0;
	}

if (ch->ptype() == PT_NDTSN && th->ack()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3000;
	#ifdef DEBUGDTSN
	printf("ACK (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), th->seqno());
	//showDtsnHeader(p, "AODV", addr());
	#endif
	if (dtsn_cached_enabled_) {
		port_dmux_->recv(pkt, (Handler*)0);
		forward = 0;
		}
	}
  
if (ch->ptype() == PT_NDTSN && th->ear()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3000;
	port_dmux_->recv(pkt, (Handler*)0);
	forward = 0;
	}

//if (ch->ptype() == PT_NDTSN && th->rnack()==0x01 && cmh->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
if (ch->ptype() == PT_NDTSN && th->rnack()==0x01 && cmh->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3000;
	port_dmux_->recv(pkt, (Handler*)0);
	forward = 0;
	}

if (ch->ptype() == PT_NDTSN && th->crnack()==0x01 && cmh->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3000;
	port_dmux_->recv(pkt, (Handler*)0);
	forward = 0;
	}

/*
 * RMST
 */
if (ch->ptype() == PT_RMST && (rh->data() || rh->eot())  && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_rmst *rhc = HDR_RMST(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3001;
	#ifdef DEBUGRMST
	printf("DATA (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), rh->seqno());
	#endif
	//if(tFile!=NULL) fprintf(tFile, "%f RECEIVED \t%d \t%d \t%d:%d \t%d:%d \t%d\n", NOW,  th->snum(), th->seqno(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), ch->num_attempts);
	port_dmux_->recv(pkt, (Handler*)0);
	}

if (ch->ptype() == PT_RMST && rh->nack()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_rmst *rhc = HDR_RMST(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3001;
	#ifdef DEBUGRMST
	printf("DATA (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), rh->seqno());
	#endif
	//if(tFile!=NULL) fprintf(tFile, "%f RECEIVED \t%d \t%d \t%d:%d \t%d:%d \t%d\n", NOW,  th->snum(), th->seqno(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), ch->num_attempts);
	port_dmux_->recv(pkt, (Handler*)0);
	forward = 0;
	}

/*
 * DTSNCC
 */
if (ch->ptype() == PT_DTSNCC && dth->data()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_dtsncc *rhc = HDR_DTSNCC(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3002;
	#ifdef DEBUGRMST
	printf("DATA (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), rh->seqno());
	#endif
	//if(tFile!=NULL) fprintf(tFile, "%f RECEIVED \t%d \t%d \t%d:%d \t%d:%d \t%d\n", NOW,  th->snum(), th->seqno(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), ch->num_attempts);
	port_dmux_->recv(pkt, (Handler*)0);
	}

if (ch->ptype() == PT_DTSNCC && dth->nack()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_dtsncc *rhc = HDR_DTSNCC(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3002;
	#ifdef DEBUGRMST
	printf("NACK (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), rh->seqno());
	#endif
	//if(tFile!=NULL) fprintf(tFile, "%f RECEIVED \t%d \t%d \t%d:%d \t%d:%d \t%d\n", NOW,  th->snum(), th->seqno(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), ch->num_attempts);
	port_dmux_->recv(pkt, (Handler*)0);
	forward = 0;
	}

if (ch->ptype() == PT_DTSNCC && dth->ack()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_dtsncc *rhc = HDR_DTSNCC(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3002;
	#ifdef DEBUGRMST
	printf("ACK (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), rh->seqno());
	#endif
	//if(tFile!=NULL) fprintf(tFile, "%f RECEIVED \t%d \t%d \t%d:%d \t%d:%d \t%d\n", NOW,  th->snum(), th->seqno(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), ch->num_attempts);
	port_dmux_->recv(pkt, (Handler*)0);
	//forward = 0;
	}

if (ch->ptype() == PT_DTSNCC && dth->rnack()==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
//if (ch->ptype() == PT_DTSNCC && dth->rnack()==0x01 && ch->direction() == hdr_cmn::UP ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_dtsncc *rhc = HDR_DTSNCC(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3002;
	port_dmux_->recv(pkt, (Handler*)0);
	forward = 0;
	//printf("RNACK (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), rh->seqno());
	}

/*
 * TCP
 */
if (ch->ptype() == PT_TCP && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_dtsncc *rhc = HDR_DTSNCC(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3004;
	#ifdef DEBUGRMST
	printf("DATA (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), rh->seqno());
	#endif
	//if(tFile!=NULL) fprintf(tFile, "%f RECEIVED \t%d \t%d \t%d:%d \t%d:%d \t%d\n", NOW,  th->snum(), th->seqno(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), ch->num_attempts);
	port_dmux_->recv(pkt, (Handler*)0);
	}

if (ch->ptype() == PT_ACK && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
	Packet *pkt;
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet
	struct hdr_ip *ihc = HDR_IP(pkt);
	struct hdr_dtsncc *rhc = HDR_DTSNCC(pkt);
	ihc->daddr() = myaddr_;
	ihc->saddr() = ih->saddr();
	ihc->dport() = 3004;
	#ifdef DEBUGRMST
	printf("ACK (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), rh->seqno());
	#endif
	//if(tFile!=NULL) fprintf(tFile, "%f RECEIVED \t%d \t%d \t%d:%d \t%d:%d \t%d\n", NOW,  th->snum(), th->seqno(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), ch->num_attempts);
	port_dmux_->recv(pkt, (Handler*)0);
	forward = 1;
	}

/*
// DTSN
if (dtsn_cached_enabled_) {  
  if (ch->ptype() == PT_DTSN && dtsnh->flags.data==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
		Packet *pkt;	
		pkt = allocpkt();
		pkt = p->copy();		// create a copy of the packet
		struct hdr_ip *ihc = HDR_IP(pkt);
		struct hdr_dtsn *dtsnc = HDR_DTSN(pkt);
		ihc->daddr() = myaddr_;
		ihc->saddr() = ih->saddr();
		ihc->dport() = 3000;	
		#ifdef DEBUGDTSN
		printf("DATA (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), dtsnh->seqno);
		//showDtsnHeader(p, "AODV", addr());
		#endif		
		//printf("\nDATA COPY(%d) src:%d sport:%d dst:%d dport:%d ", addr(), ihc->saddr(), ihc->sport(), ihc->daddr(), ihc->dport());
		//showDtsnHeader(pkt,"DATA", addr());
		//if (dtsnh->flags.rst == 0x01) {
		dtsnc->hops_to_dst = get_num_hops(ih->daddr());
		dtsnc->hops_to_src = get_num_hops(ih->saddr());
		//printf ("%d to %d: %d hops %d\n", addr(), ih->daddr(), dtsnc->hops_to_dst, dtsnc->hops_to_src );
		//}
		if (dtsn_cached_enabled_) port_dmux_->recv(pkt, (Handler*)0);
		if (dtsnh->flags.ear) {
			//printf("Node %d EAR seqno: %d\n", addr(), dtsnh->seqno);
			forward=1;
			}
		}

  if (ch->ptype() == PT_DTSN && dtsnh->flags.nack==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
		Packet *pkt;	
		pkt = allocpkt();
		pkt = p->copy();		// create a copy of the packet
		struct hdr_ip *ihc = HDR_IP(pkt);
		struct hdr_dtsn *dtsnc = HDR_DTSN(pkt);
		ihc->daddr() = myaddr_;
		ihc->saddr() = ih->saddr();
		ihc->dport() = 3000;		
		#ifdef DEBUGDTSN
		printf("NACK (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), dtsnh->seqno);
		//showDtsnHeader(p, "AODV", addr());
		#endif
		dtsnc->hops_to_dst = get_num_hops(ih->daddr());
		dtsnc->hops_to_src = get_num_hops(ih->saddr());
		//printf ("%d to %d: %d hops %d\n", addr(), ih->daddr(), dtsnc->hops_to_dst, dtsnc->hops_to_src );
		//showDtsnHeader(pkt2, "NACK", addr());
		//printf("\n<AODV> NACK src:%d sport:%d dst:%d dport:%d", ih->saddr(), ih->sport(), ih->daddr(), ih->dport());
		//if (dtsn_cached_enabled_ && !nonCaching(addr())) 
		if (dtsn_cached_enabled_) port_dmux_->recv(pkt, (Handler*)0);
		//FILE *fp;
		//fp = fopen("ack.txt", "r");
		//fscanf(fp, "%04x %04x %04x\n", &dtsnh->NACKbitmap, &dtsnh->flags.ack, &dtsnh->flags.nack);
		//fclose(fp);
		forward = 0;
	}

  if (ch->ptype() == PT_DTSN && dtsnh->flags.ack==0x01 && ch->direction() == hdr_cmn::UP && ih->daddr() != myaddr_ ) {
		Packet *pkt;	
		pkt = allocpkt();
		pkt = p->copy();		// create a copy of the packet
		struct hdr_ip *ihc = HDR_IP(pkt);
		ihc->daddr() = myaddr_;
		ihc->saddr() = ih->saddr();
		ihc->dport() = 3000;		
		#ifdef DEBUGDTSN
		printf("ACK (%d) src:%d sport:%d dst:%d dport:%d seq:%d\n", addr(), ih->saddr(), ih->sport(), ih->daddr(), ih->dport(), dtsnh->seqno);
		//showDtsnHeader(p, "AODV", addr());
		#endif
		if (dtsn_cached_enabled_) port_dmux_->recv(pkt, (Handler*)0);
	}  
}
*/
//#endif

  
  /*
   *  Must be a packet I'm originating...
   */
  if(src == myaddr_ && cmh->num_forwards() == 0) {
    /*
     * Add the IP Header
     */
    cmh->size() += IP_HDR_LEN;    
    iph->ttl_ = IP_DEF_TTL;
  }
  /*
   *  I received a packet that I sent.  Probably
   *  a routing loop.
   */
  else if(src == myaddr_) {
    drop(p, DROP_RTR_ROUTE_LOOP);
    return;
  }
  /*
   *  Packet I'm forwarding...
   */
  else {
    /*
     *  Check the TTL.  If it is zero, then discard.
     */
    if(--iph->ttl_ == 0) {
      drop(p, DROP_RTR_TTL);
      return;
    }
  }
 //do not need to update

  if ((src != myaddr_) && (iph->dport() == ROUTER_PORT))
  {
  }
  /*  {
	    // XXX disable this feature for mobileIP where
	    // the MH and FA (belonging to diff domains)
	    // communicate with each other.

	    // Drop pkt if rtg update from some other domain:
	    // if (diff_subnet(iph->src())) 
	    // drop(p, DROP_OUTSIDE_SUBNET);
	    //else    
	    processUpdate(p);
    }*/
  else if ((u_int32_t) dst == IP_BROADCAST && 
	   (iph->dport() != ROUTER_PORT)) 
	  {
	     if (src == myaddr_) {
		     // handle brdcast pkt
		     sendOutBCastPkt(p);
	     }
	     else {
		     // hand it over to the port-demux
		    
		    port_dmux_->recv(p, (Handler*)0);
	     }
	  }
  else 
    {
	    th->myaddr() = myaddr_;
	    if (forward) forwardPacket(p);
    }
}

static class FixRTClass:public TclClass
{
  public:
  FixRTClass ():TclClass ("Agent/FixRT")
  {
  }
  TclObject *create (int, const char *const *)
  {
    return (new FixRT_Agent ());
  }
} class_FixRT;

FixRT_Agent::FixRT_Agent (): Agent (PT_MESSAGE), ll_queue (0), 
  myaddr_ (0), subnet_ (0), node_ (0), port_dmux_(0),
  be_random_ (1), verbose_ (0), last_sent_(0)  
  // constants
 {
  table_ = new FixRTable();
   //DEBUG
  address = 0;
	bind("dtsn-cache-enabled", &dtsn_cached_enabled_);
}

void
FixRT_Agent::startUp()
{ 
   makeRoutingTable(ROUTE_FILE); 
}

int 
FixRT_Agent::command (int argc, const char *const *argv)
{
  if (argc == 2)
    {
      if (strcmp (argv[1], "start-fixrt") == 0)
	{
	  startUp();
	  return (TCL_OK);
	}
      else if (strcmp (argv[1], "dumprtab") == 0)
	{
	  Packet *p2 = allocpkt ();
	  hdr_ip *iph2 = HDR_IP(p2);
	  fixrt_ent  *prte;

	  printf ("Table Dump %d[%d]\n----------------------------------\n",
		  iph2->saddr(), iph2->sport());
	trace ("VTD %.5f %d:%d\n", Scheduler::instance ().clock (),
		 iph2->saddr(), iph2->sport());

	  /*
	   * Freeing a routing layer packet --> don't need to
	   * call drop here.
	   */
	Packet::free (p2);

//	  for (table_->InitLoop (); (prte = table_->NextLoop ());)
//	    output_rte ("\t", prte, this);

	  printf ("\n");

	  return (TCL_OK);
	}
      else if (strcasecmp (argv[1], "ll-queue") == 0)
	{
	if (!(ll_queue = (PriQueue *) TclObject::lookup (argv[2])))
	    {
	      fprintf (stderr, "FixRT_Agent: ll-queue lookup of %s failed\n", argv[2]);
	      return TCL_ERROR;
	    }

	  return TCL_OK;
	}

    }
  else if (argc == 3)
    {
      if (strcasecmp (argv[1], "addr") == 0) {
	 int temp;
	 temp = Address::instance().str2addr(argv[2]);
	 myaddr_ = temp;
	 return TCL_OK;
      }
      TclObject *obj;
      if ((obj = TclObject::lookup (argv[2])) == 0)
	{
	  fprintf (stderr, "%s: %s lookup of %s failed\n", __FILE__, argv[1],
		   argv[2]);
	  return TCL_ERROR;
	}
      if (strcasecmp (argv[1], "tracetarget") == 0)
	{
	  
	  tracetarget = (Trace *) obj;
	  return TCL_OK;
	}
      else if (strcasecmp (argv[1], "node") == 0) {
	      node_ = (MobileNode*) obj;
	      return TCL_OK;
      }
      else if (strcasecmp (argv[1], "port-dmux") == 0) {
	      port_dmux_ = (NsObject *) obj;
	      return TCL_OK;
      }
		//else if (strcmp(argv[1], "port-dmux") == 0) {
    //	port_dmux_ = (PortClassifier *)TclObject::lookup(argv[2]);
		//	if (port_dmux_ == 0) {
		//		fprintf (stderr, "%s: %s lookup of %s failed\n", __FILE__,
		//		argv[1], argv[2]);
		//		return TCL_ERROR;
		//		}
		//	return TCL_OK;
    //	}
	else if (strcmp(argv[1], "install-tap") == 0) {
		mac_ = (Mac*)TclObject::lookup(argv[2]);
		if (mac_ == 0) return TCL_ERROR;
		mac_->installTap(this);
		sprintf(tbuf, "dtsn_tap%d.txt", myaddr_);
		tFile = fopen(tbuf, "w");
		return TCL_OK;
		}
    } 
  
  return (Agent::command (argc, argv));
}

void
FixRT_Agent::tap(const Packet *p) {

	hdr_ndtsn *th = HDR_NDTSN(p);
	hdr_ip *ih = HDR_IP(p);
	hdr_cmn *ch = HDR_CMN(p);
	PacketStamp *t;
	
	if ( th->data() && !th->ear() && !th->ack() && !th->nack() && ch->ptype()==PT_NDTSN && get_num_hops(ih->daddr()) >= th->hops_to_dst_) {
		//printf("node: %d Packet forwarded tx:%d  seqno:%d session:%d hops_to_dst:%d\n", addr(), ih->saddr(), th->seqno(), th->snum(), th->hops_to_dst_);
		
	double Xt, Yt, Zt;		// location of transmitter
	double Xr, Yr, Zr;		// location of receiver
	int x;

	Packet *pkt;	
	pkt = allocpkt();
	pkt = p->copy();		// create a copy of the packet

	t = &pkt->txinfo_;
	t->getNode()->getLoc(&Xt, &Yt, &Zt);
	//r->getNode()->getLoc(&Xr, &Yr, &Zr);

	// Is antenna position relative to node position?
	//Xr += r->getAntenna()->getX();
	//Yr += r->getAntenna()->getY();
	//Zr += r->getAntenna()->getZ();
	Xt += t->getAntenna()->getX();
	Yt += t->getAntenna()->getY();
	Zt += t->getAntenna()->getZ();
	x = (int)(Xt/200-1) + (int)10*(Yt/220-1);
	//printf("TX location %.0f %.0f %.0f %d\n", Xt, Yt, Zt, x);
	
	if(tFile!=NULL) fprintf(tFile, "%f OVERHEARD \t%d \t%d \trecv:%d \thops_to_dst:%d \tmac_seq:%d\n", NOW, th->snum(), th->seqno(), x, th->hops_to_dst_, ch->num_attempts);
	//double dX = Xr - Xt;
	//double dY = Yr - Yt;
	//double dZ = Zr - Zt;
	//double d = sqrt(dX * dX + dY * dY + dZ * dZ);

	}
}


