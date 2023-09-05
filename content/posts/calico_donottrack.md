# How doNotTrack policies work in Calico BPF Dataplane

Almost all modern network systems, including stateful firewalls, make use of connection tracking (“conntrack”)
because it consumes less processing power per packet and simplifies operations. However, there are
use cases where connection tracking has a negative impact, as we described in
[Linux Conntrack: Why it breaks down and avoiding the problem](https://www.tigera.io/blog/when-linux-conntrack-is-no-longer-your-friend/). Distributed Denial of Service (DDoS)
mitigation systems, defending against volumetric network attacks, is a well known example of such a
use case, as it needs to drop malicious packets as fast as possible. In addition to these attacks,
connection tracking becomes a potential attack vector as it is a limited resource. There are also
applications generating huge amounts of short lived connections per second, to the point that
tracking connections leads to more processing and defeating its intended purposes. These use cases
demonstrate that there is a need to not track connections in a firewall, also known as stateless firewalling.

In this blog post, we will explain how Project Calico uses eXpress Data Path (XDP) in its eBPF dataplane
(also in its iptables dataplane but not the focus of this post) to improve the performance of its
stateless firewall. XDP is an eBPF hook that allows a program to be executed at the earliest point
in the network stack. This property makes XDP an ideal solution for implementing stateless firewalling,
i.e. doNotTrack policies in Calico, as Project Calico supports doNotTrack policies for host endpoints.
Recently, Reza Ramezanpour explained
[how to turbocharge host workloads with Calico eBPF and XDP](https://thenewstack.io/turbocharging-host-workloads-with-calico-ebpf-and-xdp/).
This article explains the details of Project Calico implementation of doNotTrack policies in its
eBPF data plane.

## Calico’s XDP architecture

Project Calico uses XDP hooks for the implementation of doNotTrack policies. Although the Calico
[eBPF architecture overview](https://projectcalico.docs.tigera.io/about/about-ebpf)
is about TC programs, the same concept is applicable to XDP programs as well.
The XDP programs have the same overall architecture as the TC program architecture, except that
connection tracking is not involved. Conntrack is not checked in the main program, and no entry is
created in the epilogue program. Every packet traverses main, policy and epilogue programs.
The execution is fast, because firstly, the main and epilogue programs are fairly simple with few
instructions. No additional processing normally performed in TC programs, like connection tracking
or NAT are executed. Secondly, the policy program only includes doNotTrack policies and not other
types of policies, which usually are fewer. The following shows the skeleton of the main programs
([source](https://github.com/projectcalico/calico/blob/master/felix/bpf-gpl/xdp.c)).

```
SEC("xdp/calico_entrypoint”)
int xdp_calico_entry(struct xdp_md *xdp)
{
  // 1 - Initialise the context, which is stored on the stack, and the state,
  // Which we use to pass data from one program to the next via tail calls
  struct cali_tc_ctx ctx = {...};

  // 2 - Parse packet
  parse_packet_ip(&ctx);

  // 3 - Fill state from packet
  state_fill_from_nexthdr(&ctx);

  // 4 - Jump to the policy program
  CALI_JUMP_TO(xdp, PROG_INDEX_POLICY);
}
```

Here’s a quick explainer of the skeleton:

1. Initializes the context variable that holds pointers to the packet and its headers, in addition
to a state structure holding packet information like source and destination addresses.
2. Parse packet.
3. Fill packet information like source and destination addresses in the state which is necessary for
the policy program.
4. Jump to the policy program.

The policy program is generated from the user space and basically is the compiled assembly code for
doNotTrack policies. Based on the result of the policy program, the traffic flow changes, and one
of the epilogue programs is executed.

### doNotTrack Policy with deny action

If the packet matches one for the doNotTrack policies with drop action, the execution moves to the
drop program to simply return `XDP_DROP` for dropping packets. It is possible to drop packets directly in the
policy program, but a dedicated program is used instead for debugging purposes like logging
and keeping a counter of dropped packets.

```
SEC("xdp/drop")
int calico_xdp_drop(struct xdp_md *xdp)
{
  // 1 - Return XDP_DROP to drop packet
  return XDP_DROP;
}
```

### doNotTrack policy with allow action

If the packet matches one of the doNotTrack policies with the accept action, we jump to the accepted
program. The most important aspect of this program is to **notify upper layers in the network stack,
like TC programs and Linux conntrack, to also not track the packet**. The interaction with the upper
layers is necessary as passing them is unavoidable.

In XDP hook, it is possible to communicate with TC programs by adding arbitrary data to the front
of packets, an area called data meta. It’s up to the programs at each side of the communication
channel to make sense of the shared bytes, i.e. meta data. Normally this is done by using a shared
structure between the XDP and TC programs, and this is exactly how Calico works. The Calico XDP program
uses a 32 bit flag to share information with the TC program. The struct is shown below and defined in the
[metadata.h](https://github.com/projectcalico/calico/blob/4bbda7d465f5df20ffb18c2f7b897cf899e9bc46/felix/bpf-gpl/metadata.h#LL11C1-L14C30) file.

```
struct cali_metadata {
  __u32  flags;
};
```

When a packet is accepted by a doNotTrack policy, the packet is sent to the TC layer with its meta data set to a special flag.

```
SEC("xdp/accept")
int calico_xdp_accepted_entrypoint(struct xdp_md *xdp)
{
  // 1 - Initialize the context and get the state
  struct cali_tc_ctx ctx = {...};

  // 2 - Share with TC the packet is already accepted and accept it there too.
  xdp2tc_set_metadata(xdp, CALI_META_ACCEPTED_BY_XDP);

  // 3 - Return XDP_PASS to let packet through to the next layer which TC
  return XDP_PASS;
}
```

TC programs detect the flag in the metadata at an early stage, which signals the packet is already
accepted by a doNotTrack policy in a XDP program, so it allows the packet to move on to upper layers.
This step happens at the beginning of the TC program, so no more processing, such as conntrack operations,
is performed.

```
// if CALI_META_ACCEPTED_BY_XDP is set in metadata
if (xdp2tc_get_metadata(skb) & CALI_META_ACCEPTED_BY_XDP)
{
  // 1 - Mark packet, so an iptables rule tells Linux Conntrack to not track this packet
  skb->mark = CALI_SKB_MARK_BYPASS;

  // 2 - Accept packet
  return TC_ACT_UNSPEC;
}
```

Moreover, at this stage, the packet mark is set to `CALI_SKB_MARK_BYPASS` to tell the Linux conntrack
to not track the packet - in case BPF cannot forward the packet on its own. This mark is checked later
on by an iptables rule in the prerouting hook of the raw table, to identify the packets that did matched
with a doNotTrack policy, and jump to a custom table, where the packet mark is cleared, and
the Linux conntrack is notified to not to track this packet:

```
-A cali-PREROUTING -m mark --mark CALI_SKB_MARK_BYPASS -g cali-untracked-policy

-A cali-untracked-policy -j MARK --set-xmark 0x0/0x0
-A cali-untracked-policy -j NOTRACK
```

Because there is no conntrack, we are not able to tell that the traffic was allowed, therefore the
downside is that we need to have the opposite policy too. The implication is that a policy is needed
to accept the reverse packets if applications want to communicate in both directions. As such, the
*do not track* semantics also need to be implemented for the reverse path as well.

The XDP hook is only available in an ingress path, since the main motivation for XDP hook is to execute
eBPF code at the earliest possible execution point, which is usually at a NIC’s driver. However, in
an egress path, NIC is almost the last execution point, which makes the XDP hook in egress useless.
For that reason, the XDP hook is available only in an ingress direction.

Since Calico implements do not track policies only for host endpoints, packets in the egress path
are only packets generated by the local host. In effect, such packets first hit iptables and then
TC hooks before leaving the host. For that reason, doNotTrack policy for egress direction is
implemented in iptables, where packets accepted by a rule are marked to be accepted by TC programs
early on before performing any conntrack operations.

Below is an example of a doNotTrack policy for egress path, where the accepted packets are set to not
be tracked by Linux conntrack, and marked with `CALI_SKB_MARK_BYPASS` to also inform TC programs to accept
without tracking these packets. All these steps allow a traffic flow untracked in both directions.

```
-A cali-OUTPUT -j cali-to-host-endpoint
-A cali-OUTPUT -m mark --mark 0x10000/0x10000 -j MARK --set-xmark CALI_SKB_MARK_BYPASS
-A cali-OUTPUT -m mark --mark CALI_SKB_MARK_BYPASS -j ACCEPT

-A cali-to-host-endpoint -o eth0 -g cali-th-eth0
-A cali-th-eth0 -m mark --mark 0x0/0x20000 -j cali-po-default.host-0-pol
-A cali-th-eth0 -m mark --mark 0x10000/0x10000 -j NOTRACK

-A cali-po-default.host-0-pol -m set --match-set ... -j MARK --set-xmark 0x10000/0x10000
```

### No doNotTrack policy matched

If none of the doNotTrack policies are matched in the policy program, the packet is accepted by
returning `XDP_PASS` directly in the policy program without setting any meta data. Then, the packet is
sent to TC programs to go through normal processing flow which includes matching conntracks.

## Performance

There are two key elements affecting the performance of untracked policies:
1. Per packet processing in a connection
2. Policy enforcement point

Firstly, most network systems take advantage of connection tracking to reduce per packet processing.
However, for few niche applications such as the ones that generate a huge amount of short lived
connections per second like some databases, it’s faster to process each packet independently rather
than keeping track of connections. Calico doNotTrack policies with Accept action targets this sort of
application.

Secondly, the performance boost in doNotTrack policies with Drop action comes from the policy
enforcement point. For this type of policy, Calico eBPF dataplane, uses XDP hook to drop packets as
soon as possible without wasting any extra resources. This allows Calico to defend against DDoS attacks.

## Conclusion

Connection tracking is an essential part of a network system. However, there are use cases like defending
against a DDoS attack which negates its benefits. In this post, we explored how Calico eBPF dataplane
uses XDP hooks to implement its stateless firewalling, i.e. doNotTrack policies. Using XDP which is
the earliest point of execution for an eBPF program boosts the performance substantially in the
ingress path, specially with Drop action.
