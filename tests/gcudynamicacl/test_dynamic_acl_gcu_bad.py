import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert, pytest_require


import ptf.mask as mask
import ptf.packet as packet
import random


import ptf.testutils as testutils

from collections import defaultdict

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

from tests.common.utilities import get_upstream_neigh_type, get_downstream_neigh_type

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

DEFAULT_SRC_IP = {
    "ipv4": "20.0.0.1",
    "ipv6": "60c0:a800::5"
}

DOWNSTREAM_DST_IP = {
    "ipv4": "192.168.0.253",
    "ipv6": "20c0:a800::14"
}
DOWNSTREAM_IP_TO_ALLOW = {
    "ipv4": "192.168.0.252",
    "ipv6": "20c0:a800::1"
}
DOWNSTREAM_IP_TO_BLOCK = {
    "ipv4": "192.168.0.251",
    "ipv6": "20c0:a800::9"
}

UPSTREAM_DST_IP = {
    "ipv4": "194.50.16.1",
    "ipv6": "20c1:d180::11"
}
UPSTREAM_IP_TO_ALLOW = {
    "ipv4": "193.191.32.1",
    "ipv6": "20c1:cb50::12"
}
UPSTREAM_IP_TO_BLOCK = {
    "ipv4": "193.221.112.1",
    "ipv6": "20c1:e2f0::13"
}

VLAN_BASE_MAC_PATTERN = "72060001{:04}"

DUT_TMP_DIR = "acl_test_dir"

@pytest.fixture(scope="module")
def setup(duthosts, ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo, ptfadapter, topo_scenario, vlan_name):
    """Gather all required test information from DUT and tbinfo.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        tbinfo: A fixture to gather information about the testbed.

    Yields:
        A Dictionary with required test information.

    """

    pytest_assert(vlan_name in ["Vlan1000", "Vlan2000", "no_vlan"], "Invalid vlan name.")
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["type"]

    vlan_ports = []
    vlan_mac = None
    # Need to refresh below constants for two scenarios of M0
    global DOWNSTREAM_DST_IP, DOWNSTREAM_IP_TO_ALLOW, DOWNSTREAM_IP_TO_BLOCK
    
    vlan_ports = [mg_facts["minigraph_ptf_indices"][ifname]
                    for ifname in mg_facts["minigraph_vlans"][vlan_name]["members"]]

    config_facts = rand_selected_dut.get_running_config_facts()
    vlan_table = config_facts["VLAN"]
    if "mac" in vlan_table[vlan_name]:
        vlan_mac = vlan_table[vlan_name]["mac"]

    # Get the list of upstream/downstream ports
    downstream_ports = defaultdict(list)
    upstream_ports = defaultdict(list)
    downstream_port_ids = []
    upstream_port_ids = []
    upstream_port_id_to_router_mac_map = {}
    downstream_port_id_to_router_mac_map = {}

    downlink_dst_mac = vlan_mac if vlan_mac is not None else rand_selected_dut.facts["router_mac"]

    upstream_neigh_type = get_upstream_neigh_type(topo)
    downstream_neigh_type = get_downstream_neigh_type(topo)
    pytest_require(upstream_neigh_type is not None and downstream_neigh_type is not None,
                    "Cannot get neighbor type for unsupported topo: {}".format(topo))
    mg_vlans = mg_facts["minigraph_vlans"]
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if downstream_neigh_type in neighbor["name"].upper():
            if topo in ["t0", "mx", "m0_vlan"]:
                if interface not in mg_vlans[vlan_name]["members"]:
                    continue

            downstream_ports[neighbor['namespace']].append(interface)
            downstream_port_ids.append(port_id)
            downstream_port_id_to_router_mac_map[port_id] = downlink_dst_mac
        elif upstream_neigh_type in neighbor["name"].upper():
            upstream_ports[neighbor['namespace']].append(interface)
            upstream_port_ids.append(port_id)
            upstream_port_id_to_router_mac_map[port_id] = rand_selected_dut.facts["router_mac"]

    # stop garp service for single tor
    if 'dualtor' not in tbinfo['topo']['name']:
        logging.info("Stopping GARP service on single tor")
        ptfhost.shell("supervisorctl stop garp_service", module_ignore_errors=True)

    # If running on a dual ToR testbed, any uplink for either ToR is an acceptable
    # source or destination port
    if 'dualtor' in tbinfo['topo']['name'] and rand_unselected_dut is not None:
        peer_mg_facts = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
        for interface, neighbor in list(peer_mg_facts['minigraph_neighbors'].items()):
            if (topo == "t1" and "T2" in neighbor["name"]) or (topo == "t0" and "T1" in neighbor["name"]):
                port_id = peer_mg_facts["minigraph_ptf_indices"][interface]
                upstream_port_ids.append(port_id)
                upstream_port_id_to_router_mac_map[port_id] = rand_unselected_dut.facts["router_mac"]

    # Get the list of LAGs
    port_channels = mg_facts["minigraph_portchannels"]

    # TODO: We should make this more robust (i.e. bind all active front-panel ports)
    acl_table_ports = defaultdict(list)

    for namespace, port in list(downstream_ports.items()):
        acl_table_ports[namespace] += port
        # In multi-asic we need config both in host and namespace.
        if namespace:
            acl_table_ports[''] += port

    for k, v in list(port_channels.items()):
        acl_table_ports[v['namespace']].append(k)
        # In multi-asic we need config both in host and namespace.
        if v['namespace']:
            acl_table_ports[''].append(k)

    dest_mac_mapping = {
        "downlink->uplink": downstream_port_id_to_router_mac_map,
        "uplink->downlink": upstream_port_id_to_router_mac_map
    }

    setup_information = {
        "destination_mac": dest_mac_mapping,
        "downstream_port_ids": downstream_port_ids,
        "upstream_port_ids": upstream_port_ids,
        "acl_table_ports": acl_table_ports,
        "vlan_ports": vlan_ports,
        "topo": topo,
        "vlan_mac": vlan_mac
    }

    logger.info("Creating temporary folder \"{}\" for ACL test".format(DUT_TMP_DIR))
    for duthost in duthosts:
        duthost.command("mkdir -p {}".format(DUT_TMP_DIR))

    yield setup_information

    logger.info("Removing temporary directory \"{}\"".format(DUT_TMP_DIR))
    for duthost in duthosts:
        duthost.command("rm -rf {}".format(DUT_TMP_DIR))

def get_src_port(setup, direction):
    """Get a source port for the current test."""
    src_ports = setup["downstream_port_ids"] if direction == "downlink->uplink" else setup["upstream_port_ids"]
    src_port = random.choice(src_ports)
    logger.info("Selected source port {}".format(src_port))
    return src_port

def get_dst_ports(setup, direction):
    """Get the set of possible destination ports for the current test."""
    return setup["upstream_port_ids"] if direction == "downlink->uplink" else setup["downstream_port_ids"]

def get_dst_ip(direction, ip_version):
    """Get the default destination IP for the current test."""
    return UPSTREAM_DST_IP[ip_version] if direction == "downlink->uplink" else DOWNSTREAM_DST_IP[ip_version]

def tcp_packet(setup, direction, ptfadapter, ip_version,
                   src_ip=None, dst_ip=None, proto=None, sport=0x4321, dport=0x51, flags=None):
        """Generate a TCP packet for testing."""
        src_ip = src_ip or DEFAULT_SRC_IP[ip_version]
        dst_ip = dst_ip or get_dst_ip(direction, ip_version)
        src_port = get_src_port(setup, direction)
        if ip_version == "ipv4":
            pkt = testutils.simple_tcp_packet(
                eth_dst=setup["destination_mac"][direction][src_port],
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ip_dst=dst_ip,
                ip_src=src_ip,
                tcp_sport=sport,
                tcp_dport=dport,
                ip_ttl=64
            )

            if proto:
                pkt["IP"].proto = proto
        else:
            pkt = testutils.simple_tcpv6_packet(
                eth_dst=setup["destination_mac"][direction][src_port],
                eth_src=ptfadapter.dataplane.get_mac(0, 0),
                ipv6_dst=dst_ip,
                ipv6_src=src_ip,
                tcp_sport=sport,
                tcp_dport=dport,
                ipv6_hlim=64
            )

            if proto:
                pkt["IPv6"].nh = proto

        if flags:
            pkt["TCP"].flags = flags

        return pkt

def expected_mask_routed_packet(self, pkt, ip_version):
        """Generate the expected mask for a routed packet."""
        exp_pkt = pkt.copy()

        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(packet.Ether, "src")

        if ip_version == "ipv4":
            exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
            # In multi-asic we cannot determine this so ignore.
            exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
        else:
            # In multi-asic we cannot determine this so ignore.
            exp_pkt.set_do_not_care_scapy(packet.IPv6, 'hlim')

        return exp_pkt

def verify_expected_packet_behavior(exp_pkt, ptfadapter, dst_ports, expect_drop):
    if expect_drop:
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=dst_ports)
    else:
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=dst_ports,
                                        timeout=20)
        
def _verify_acl_traffic(self, setup, direction, ptfadapter, pkt, dropped, ip_version):
        exp_pkt = self.expected_mask_routed_packet(pkt, ip_version)

        if ip_version == "ipv4":
            downstream_dst_port = DOWNSTREAM_IP_PORT_MAP.get(pkt[packet.IP].dst)
        else:
            downstream_dst_port = DOWNSTREAM_IP_PORT_MAP.get(pkt[packet.IPv6].dst)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, self.src_port, pkt)
        if direction == "uplink->downlink" and downstream_dst_port:
            if dropped:
                testutils.verify_no_packet(ptfadapter, exp_pkt, downstream_dst_port)
            else:
                testutils.verify_packet(ptfadapter, exp_pkt, downstream_dst_port)
        else:
            if dropped:
                testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction))
            else:
                testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=self.get_dst_ports(setup, direction),
                                                 timeout=20)

def generate_forward_packets(router_mac):
    DST_IP = "103.23.2.1"
    DST_IPV6 = "103:23:2:1::1"

    forward_packets = {}

    forward_packets["IPV4"] = testutils.simple_tcp_packet(eth_dst=router_mac,
                                ip_src='192.168.0.3',
                                ip_dst=DST_IP)
    
    forward_packets["IPV6"] = testutils.simple_tcpv6_packet(eth_dst=router_mac,
                                ipv6_src='fc02:1000::3',
                                ipv6_dst=DST_IPV6)
    
    return forward_packets


def generate_drop_packets(router_mac):
    DST_IP = "103.23.3.1"
    DST_IPV6 = "103:23:3:1::1"

    drop_packets = {}

    drop_packets["IPV4"] = testutils.simple_tcp_packet(eth_dst=router_mac,
                                ip_src='192.168.0.3',
                                ip_dst=DST_IP)
    
    drop_packets["IPV6"] = testutils.simple_tcpv6_packet(eth_dst=router_mac,
                                ipv6_src='fc02:1000::3',
                                ipv6_dst=DST_IPV6)
    
    return drop_packets

def expect_acl_table_match_multiple_bindings(duthost, table_name, expected_first_line_content, expected_bindings):
    """Check if acl table show as expected
    Acl table with multiple bindings will show as such

    Table_Name  Table_Type  Ethernet4   Table_Description   ingress
                            Ethernet8
                            Ethernet12
                            Ethernet16

    So we must have separate checks for first line and bindings
    """
    cmds = "show acl table {}".format(table_name)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # Ignore first two lines display. lines less than 3 means no output
    # Use empty list if no output
    lines = output['stdout'].splitlines()
    first_line = [] if len(lines) < 3 else lines[2].split()
    # Ignore the status column
    expected_len = len(expected_first_line_content)
    if len(first_line) >= expected_len:
        first_line = first_line[0:expected_len]

    pytest_assert(set(expected_first_line_content) == set(first_line), "ACL table definition doesn't match")
    bindings = [line.strip() for line in lines[3:]]
    #Second element of the first line is the first binding
    bindings.append(first_line[2])

    pytest_assert(set(bindings) == set(expected_bindings))

def expect_acl_rule_match(duthost, rulename, expected_content_list):
    """Check if acl rule shows as expected"""

    cmds = "show acl rule | grep {}".format(rulename)
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    lines = output['stdout'].splitlines()
    actual_list = lines[0].split()

    # Ignore the status column
    expected_len = len(expected_content_list)
    if len(actual_list) >= expected_len:
        actual_list = actual_list[0:expected_len]

    pytest_assert(set(expected_content_list) == set(actual_list), "ACL rule does not match!")

def expect_acl_rule_removed(duthost, rulename):
    """Check if ACL rule has been successfully removed"""

    cmds = "show acl rule {}".format(rulename)
    output = duthost.shell(cmds)

    removed = len(output['stdout'].splitlines()) <= 2

    pytest_assert(removed, "'{}' showed a rule, this following rule should have been removed: {}".format(cmds, output['stdout']))
    
def dynamic_acl_create_table_type(duthost):
    """Create a new ACL table type that can be used"""
    json_patch = [
        {
            "op": "add", 
            "path": "/ACL_TABLE_TYPE", 
            "value": { 
                "DYNAMIC_ACL_TABLE_TYPE" : { 
                "MATCHES": ["DST_IP","DST_IPV6","ETHER_TYPE","IN_PORTS"], 
                "ACTIONS": ["PACKET_ACTION","COUNTER"], 
                "BIND_POINTS": ["PORT"] 
                }                        
            }                                
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_create_table(duthost):
    """Create a new ACL table type that can be used"""
    json_patch = [
        {
            "op": "add", 
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE", 
            "value": { 
                "policy_desc": "DYNAMIC_ACL_TABLE", 
                "type": "DYNAMIC_ACL_TABLE_TYPE", 
                "stage": "INGRESS", 
                "ports": ["Ethernet4","Ethernet8","Ethernet12","Ethernet16","Ethernet20","Ethernet24","Ethernet28","Ethernet32","Ethernet36","Ethernet40","Ethernet44","Ethernet48","Ethernet52","Ethernet56","Ethernet60","Ethernet64","Ethernet68","Ethernet72","Ethernet76","Ethernet80","Ethernet84","Ethernet88","Ethernet92","Ethernet96"] 
            }                        
        }
    ]

    expected_bindings = ["Ethernet4","Ethernet8","Ethernet12","Ethernet16","Ethernet20","Ethernet24","Ethernet28","Ethernet32","Ethernet36","Ethernet40","Ethernet44","Ethernet48","Ethernet52","Ethernet56","Ethernet60","Ethernet64","Ethernet68","Ethernet72","Ethernet76","Ethernet80","Ethernet84","Ethernet88","Ethernet92","Ethernet96"] 
    expected_first_line = ["DYNAMIC_ACL_TABLE", "DYNAMIC_ACL_TABLE_TYPE", "Ethernet4", "DYNAMIC_ACL_TABLE", "ingress"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_table_match_multiple_bindings(duthost, "DYNAMIC_ACL_TABLE", expected_first_line, expected_bindings)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_create_duplicate_table(duthost):
    """Create a duplicate ACL table type that should fail"""
    json_patch = [
        {
            "op": "add", 
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE", 
            "value": { 
                "policy_desc": "DYNAMIC_ACL_TABLE", 
                "type": "DYNAMIC_ACL_TABLE_TYPE", 
                "stage": "INGRESS", 
                "ports": ["Ethernet4","Ethernet8","Ethernet12","Ethernet16","Ethernet20","Ethernet24","Ethernet28","Ethernet32","Ethernet36","Ethernet40","Ethernet44","Ethernet48","Ethernet52","Ethernet56","Ethernet60","Ethernet64","Ethernet68","Ethernet72","Ethernet76","Ethernet80","Ethernet84","Ethernet88","Ethernet92","Ethernet96"] 
            }                        
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_create_forward_rules(duthost):
    """Create forward ACL rules"""

    json_patch = [ 
        { 
            "op": "add", 
            "path": "/ACL_RULE", 
            "value": { 
                "DYNAMIC_ACL_TABLE|RULE_1": {
                    "DST_IP": "103.23.2.1/32", 
                    "PRIORITY": "9999", 
                    "PACKET_ACTION": "FORWARD" 
                }, 
                "DYNAMIC_ACL_TABLE|RULE_2": {
                    "DST_IPV6": "103:23:2:1::1/128", 
                    "PRIORITY": "9998", 
                    "PACKET_ACTION": "FORWARD" 
                }
            }                                                                                                                               
        } 
    ] 

    expected_rule_1_content = ["DYNAMIC_ACL_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP:", "103.23.2.1/32"]
    expected_rule_2_content = ["DYNAMIC_ACL_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6:",  "103:23:2:1::1/128"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
        expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)
    finally:
        delete_tmpfile(duthost, tmpfile)


def dynamic_acl_create_drop_rule(duthost):
    """Create a drop rule"""

    json_patch = [
        { 
            "op": "add", 
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_3", 
            "value": { 
                "PRIORITY": "9997", 
                "PACKET_ACTION": "DROP", 
                "IN_PORTS": "Ethernet4" 
            }                                                                                                                               
        } 
    ]

    expected_rule_content = ["DYNAMIC_ACL_TABLE", "RULE_3", "9997" , "DROP", "IN_PORTS:", "Ethernet4"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_3", expected_rule_content)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_verify_packets(duthost, tbinfo, ptfadapter, packets_dropped):

    #Get information from the dut that will be used to build and send packets correctly during testing
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if "dualtor" in tbinfo["topo"]["name"]:
        vlan_name = list(mg_facts['minigraph_vlans'].keys())[0]
        # Use VLAN MAC as router MAC on dual-tor testbed
        router_mac = duthost.get_dut_iface_mac(vlan_name)
    else:
        router_mac = duthost.facts['router_mac']

    # Selected the first vlan port as source port
    src_port = list(mg_facts['minigraph_vlans'].values())[0]['members'][0]
    src_port_indice = mg_facts['minigraph_ptf_indices'][src_port]
    # Put all portchannel members into dst_ports
    dst_port_indices = []
    for _, v in mg_facts['minigraph_portchannels'].items():
        for member in v['members']:
            dst_port_indices.append(mg_facts['minigraph_ptf_indices'][member])

    if packets_dropped:
        test_pkts = generate_drop_packets(router_mac)
    else:
        test_pkts = generate_forward_packets(router_mac)
    for rule, pkt in list(test_pkts.items()):
        logger.info("Testing that {} packets are correctly dropped".format(rule))
        exp_pkt = build_exp_pkt(pkt)
        # Send and verify packet
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, pkt=pkt, port_id=src_port_indice)
        verify_expected_packet_behavior(exp_pkt, ptfadapter, dst_port_indices, expect_drop=packets_dropped)

def dynamic_acl_remove_drop_rule(duthost):
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_3", 
            "value":{}                                                                                                                               
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_removed(duthost, "RULE_3")
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_replace_nonexistant_rule(duthost):
    json_patch = [ 
        { 
            "op": "replace", 
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_10", 
            "value": { 
                "DST_IP": "103.23.2.2/32", 
                "PRIORITY": "9999", 
                "PACKET_ACTION": "FORWARD" 
            }                                                                                                                               
        }
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_replace_rules(duthost):
    json_patch = [ 
        { 
            "op": "replace", 
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_1", 
            "value": { 
                "DST_IP": "103.23.2.2/32", 
                "PRIORITY": "9999", 
                "PACKET_ACTION": "FORWARD" 
            }                                                                                                                               
        }, 
        { 
        "op": "replace", 
        "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_2", 
            "value": { 
                "DST_IPV6": "103:23:2:1::2/128", 
                "PRIORITY": "9998", 
                "PACKET_ACTION": "FORWARD" 
            }                                                                                                                               
        } 
    ] 

    expected_rule_1_content = ["DYNAMIC_ACL_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP:", "103.23.2.2/32"]
    expected_rule_2_content = ["DYNAMIC_ACL_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6:",  "103:23:2:1::2/128"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_match(duthost, "RULE_1", expected_rule_1_content)
        expect_acl_rule_match(duthost, "RULE_2", expected_rule_2_content)
    finally:
        delete_tmpfile(duthost, tmpfile)


def dynamic_acl_remove_forward_rules(duthost):
    """Remove our two forward rules from the acl table
    As the second operation would leave the table empty, we remove the whole ACL_RULE table instead of RULE_2"""
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_1", 
            "value":{}                                                                                                                               
        }, 
        { 
            "op": "remove", 
            "path": "/ACL_RULE", 
            "value": { }                                                                                                                               
        } 
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        expect_acl_rule_removed(duthost, "RULE_1")
        expect_acl_rule_removed(duthost, "RULE_2")
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_table(duthost):
    """Remove an ACL Table Type from the duthost"""
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE", 
            "value": { }                                                                                                                                        
        } 
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_nonexistant_table(duthost):
    """Remove an ACL Table from the duthost"""
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE_BAD", 
            "value": { }                                                                                                                                        
        } 
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_failure(output)
    finally:
        delete_tmpfile(duthost, tmpfile)

def dynamic_acl_remove_table_type(duthost):
    """Remove an ACL Table definition from the duthost
    As we only have one ACL Table definition on """
    json_patch = [ 
        { 
            "op": "remove", 
            "path": "/ACL_TABLE_TYPE", 
            "value": { }                                                                                                                                        
        } 
    ] 

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)



def test_dynamic_acl_test(rand_selected_dut, tbinfo, ptfadapter):

    #Get information from the dut that will be used to build and send packets correctly during testing
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    if "dualtor" in tbinfo["topo"]["name"]:
        vlan_name = list(mg_facts['minigraph_vlans'].keys())[0]
        # Use VLAN MAC as router MAC on dual-tor testbed
        router_mac = rand_selected_dut.get_dut_iface_mac(vlan_name)
    else:
        router_mac = rand_selected_dut.facts['router_mac']

    # Selected the first vlan port as source port
    src_port = list(mg_facts['minigraph_vlans'].values())[0]['members'][0]
    src_port_indice = mg_facts['minigraph_ptf_indices'][src_port]
    # Put all portchannel members into dst_ports
    dst_port_indices = []
    for _, v in mg_facts['minigraph_portchannels'].items():
        for member in v['members']:
            dst_port_indices.append(mg_facts['minigraph_ptf_indices'][member])

    dynamic_acl_create_table_type(rand_selected_dut)
    dynamic_acl_create_table(rand_selected_dut)
    dynamic_acl_create_duplicate_table(rand_selected_dut)
    dynamic_acl_create_forward_rules(rand_selected_dut)
    dynamic_acl_create_drop_rule(rand_selected_dut)
    dynamic_acl_verify_packets(rand_selected_dut, tbinfo, ptfadapter, packets_dropped=True) #Verify that packets not forwarded are universally dropped
    dynamic_acl_verify_packets(rand_selected_dut, tbinfo, ptfadapter, packets_dropped=False) #Verify that packets are correctly forwarded
    dynamic_acl_remove_drop_rule(rand_selected_dut)
    dynamic_acl_replace_nonexistant_rule(rand_selected_dut)
    dynamic_acl_replace_rules(rand_selected_dut)
    dynamic_acl_remove_forward_rules(rand_selected_dut)
    dynamic_acl_remove_nonexistant_table(rand_selected_dut)
    dynamic_acl_remove_table(rand_selected_dut)
    dynamic_acl_remove_table_type(rand_selected_dut)

