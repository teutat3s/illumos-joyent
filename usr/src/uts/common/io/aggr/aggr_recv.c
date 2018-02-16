/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 OmniTI Computer Consulting, Inc  All rights reserved.
 */

/*
 * IEEE 802.3ad Link Aggregation - Receive
 *
 * Implements the collector function.
 * Manages the RX resources exposed by a link aggregation group.
 */

#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/byteorder.h>
#include <sys/aggr.h>
#include <sys/aggr_impl.h>

static void
aggr_mac_rx(mac_handle_t lg_mh, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t promisc_path)
{
	if (promisc_path) {
		mac_aggr_promisc_dispatch(lg_mh, mp);
		return;
	}

	if (mrh == NULL) {
		mac_rx(lg_mh, mrh, mp);
	} else {
		aggr_pseudo_rx_ring_t	*ring = (aggr_pseudo_rx_ring_t *)mrh;
		mac_rx_ring(lg_mh, ring->arr_rh, mp, ring->arr_gen);
	}
}

/* ARGSUSED */
void
aggr_recv_lacp(aggr_port_t *port, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t promisc_path)
{
	aggr_grp_t *grp = port->lp_grp;

	/* in promiscuous mode, send copy of packet up */
	if (promisc_path) {
		mblk_t *nmp = copymsg(mp);

		/*
		 * rpz: Don't call aggr_mac_rx(). Instead, reach into
		 * the aggr's mci_promisc_list and perform promisc
		 * dispatch here to prevent dup delivery during normal Rx.
		 */
		if (nmp != NULL)
			mac_aggr_promisc_dispatch(grp->lg_mh, mp);

		/*
		 * rpz: Only deliver to promisc cb on promisc path.
		 */
		return;
	}

	aggr_lacp_rx_enqueue(port, mp);
}

/*
 * Callback function invoked by MAC service module when packets are
 * made available by a MAC port, both in promisc_on mode and not.
 */
/* ARGSUSED */
static void
aggr_recv_path_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback, boolean_t promisc_path)
{
	aggr_port_t *port = (aggr_port_t *)arg;
	aggr_grp_t *grp = port->lp_grp;

	/* In the case where lp_promisc_on has been turned on to
	 * compensate for insufficient hardware MAC matching and
	 * hardware rings are not in use we will fall back to
	 * using flows for delivery which can result in duplicates
	 * pushed up the stack. Only respect the chosen path.
	 */

	/*
	 * rpz: I'm removing this logic because now when promisc is
	 * enabled aggr will have separate data paths: one dedicated
	 * to promisc and another to normal Rx. But this function is
	 * still shared by both datapaths to enforce the LACP logic.
	 *
	 * if (port->lp_promisc_on != promisc_path) {
	 * 	freemsgchain(mp);
	 * 	return;
	 * }
	 */

	if (grp->lg_lacp_mode == AGGR_LACP_OFF) {
		aggr_mac_rx(grp->lg_mh, mrh, mp, promisc_path);
	} else {
		mblk_t *cmp, *last, *head;
		struct ether_header *ehp;
		uint16_t sap;

		/* filter out slow protocol packets (LACP & Marker) */
		last = NULL;
		head = cmp = mp;
		while (cmp != NULL) {
			if (MBLKL(cmp) < sizeof (struct ether_header)) {
				/* packet too short */
				if (head == cmp) {
					/* no packets accumulated */
					head = cmp->b_next;
					cmp->b_next = NULL;
					freemsg(cmp);
					cmp = head;
				} else {
					/* send up accumulated packets */
					last->b_next = NULL;
					if (port->lp_collector_enabled) {
						aggr_mac_rx(grp->lg_mh, mrh,
						    head, promisc_path);
					} else {
						/* rpz: kstat? */
						freemsgchain(head);
					}
					head = cmp->b_next;
					cmp->b_next = NULL;
					freemsg(cmp);
					cmp = head;
					last = NULL;
				}
				continue;
			}
			ehp = (struct ether_header *)cmp->b_rptr;

			sap = ntohs(ehp->ether_type);
			if (sap == ETHERTYPE_SLOW) {
				/*
				 * LACP or Marker packet. Send up pending
				 * chain, and send LACP/Marker packet
				 * to LACP subsystem.
				 */
				if (head == cmp) {
					/* first packet of chain */
					ASSERT(last == NULL);
					head = cmp->b_next;
					cmp->b_next = NULL;
					aggr_recv_lacp(port, mrh, cmp,
					    promisc_path);
					cmp = head;
				} else {
					/* previously accumulated packets */
					ASSERT(last != NULL);
					/* send up non-LACP packets */
					last->b_next = NULL;
					if (port->lp_collector_enabled) {
						aggr_mac_rx(grp->lg_mh, mrh,
						    head, promisc_path);
					} else {
						/* rpz: kstat? */
						freemsgchain(head);
					}
					/* unlink and pass up LACP packets */
					head = cmp->b_next;
					cmp->b_next = NULL;
					aggr_recv_lacp(port, mrh, cmp,
					    promisc_path);
					cmp = head;
					last = NULL;
				}
			} else {
				last = cmp;
				cmp = cmp->b_next;
			}
		}
		if (head != NULL) {
			if (port->lp_collector_enabled)
				aggr_mac_rx(grp->lg_mh, mrh, head,
				    promisc_path);
			else
				freemsgchain(head); /* rpz: kstat? */
		}
	}
}

/* ARGSUSED */
void
aggr_recv_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	aggr_recv_path_cb(arg, mrh, mp, loopback, B_FALSE);
}

/* ARGSUSED */
void
aggr_recv_promisc_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	aggr_recv_path_cb(arg, mrh, mp, loopback, B_TRUE);
}
