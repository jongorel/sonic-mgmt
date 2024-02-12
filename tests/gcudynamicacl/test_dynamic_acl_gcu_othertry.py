import os
import time
import random
import logging
import pprint
import pytest
import json
import six
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from abc import ABCMeta, abstractmethod
from collections import defaultdict

from tests.common import reboot, port_toggle
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.config_reload import config_reload
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py, run_garp_service, change_mac_addresses   # noqa F401
from tests.common.utilities import wait_until
from tests.common.dualtor.dual_tor_mock import mock_server_base_ip_addr # noqa F401
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import get_upstream_neigh_type, get_downstream_neigh_type
from tests.common.fixtures.conn_graph_facts import conn_graph_facts # noqa F401
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.interface_utils import check_all_interface_information

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.acl,
    pytest.mark.disable_loganalyzer,  # Disable automatic loganalyzer, since we use it for the test
    pytest.mark.topology("t0", "t1", "t2", "m0", "mx"),
]

MAX_WAIT_TIME_FOR_INTERFACES = 360

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = "acl_test_dir"  # Keep it under home dir so it persists through reboot
FILES_DIR = os.path.join(BASE_DIR, "files")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

ACL_TABLE_TEMPLATE = "acltb_table.j2"
ACL_REMOVE_RULES_FILE = "acl_rules_del.json"

# TODO: We really shouldn't have two separate templates for v4 and v6, need to combine them somehow
ACL_RULES_FULL_TEMPLATE = {
    "ipv4": "acltb_test_rules.j2",
    "ipv6": "acltb_v6_test_rules.j2"
}
ACL_RULES_PART_TEMPLATES = {
    "ipv4": tuple("acltb_test_rules_part_{}.j2".format(i) for i in range(1, 3)),
    "ipv6": tuple("acltb_v6_test_rules_part_{}.j2".format(i) for i in range(1, 3))
}

DEFAULT_SRC_IP = {
    "ipv4": "20.0.0.1",
    "ipv6": "60c0:a800::5"
}


# TODO: These routes don't match the VLAN interface from the T0 topology.
# This needs to be addressed before we can enable the v6 tests for T0
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

# Below M0_L3 IPs are announced to DUT by annouce_route.py, it point to neighbor mx
DOWNSTREAM_DST_IP_M0_L3 = {
    "ipv4": "192.168.1.65",
    "ipv6": "20c0:a800:0:1::14"
}
DOWNSTREAM_IP_TO_ALLOW_M0_L3 = {
    "ipv4": "192.168.1.66",
    "ipv6": "20c0:a800:0:1::1"
}
DOWNSTREAM_IP_TO_BLOCK_M0_L3 = {
    "ipv4": "192.168.1.67",
    "ipv6": "20c0:a800:0:1::9"
}

# Below M0_VLAN IPs are ip in vlan range
DOWNSTREAM_DST_IP_VLAN = {
    "ipv4": "192.168.0.123",
    "ipv6": "fc02:1000::5"
}
DOWNSTREAM_IP_TO_ALLOW_VLAN = {
    "ipv4": "192.168.0.122",
    "ipv6": "fc02:1000::6"
}
DOWNSTREAM_IP_TO_BLOCK_VLAN = {
    "ipv4": "192.168.0.121",
    "ipv6": "fc02:1000::7"
}

DOWNSTREAM_DST_IP_VLAN2000 = {
    "ipv4": "192.168.0.253",
    "ipv6": "fc02:1000:0:1::5"
}
DOWNSTREAM_IP_TO_ALLOW_VLAN2000 = {
    "ipv4": "192.168.0.252",
    "ipv6": "fc02:1000:0:1::6"
}
DOWNSTREAM_IP_TO_BLOCK_VLAN2000 = {
    "ipv4": "192.168.0.251",
    "ipv6": "fc02:1000:0:1::7"
}

DOWNSTREAM_IP_PORT_MAP = {}

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

LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_TABLE_REMOVE_RE = ".*Successfully deleted ACL table.*"
LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"
LOG_EXPECT_ACL_RULE_REMOVE_RE = ".*Successfully deleted ACL rule.*"

PACKETS_COUNT = "packets_count"
BYTES_COUNT = "bytes_count"


@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(duthosts):
    """
    Remove DATAACL to free TCAM resources.
    The change is written to configdb as we don't want DATAACL recovered after reboot
    """
    TABLE_NAME = "DATAACL"
    for duthost in duthosts:
        lines = duthost.shell(cmd="show acl table {}".format(TABLE_NAME))['stdout_lines']
        data_acl_existing = False
        for line in lines:
            if TABLE_NAME in line:
                data_acl_existing = True
                break
        if data_acl_existing:
            # Remove DATAACL
            logger.info("Removing ACL table {}".format(TABLE_NAME))
            cmds = [
                "config acl remove table {}".format(TABLE_NAME),
                "config save -y"
            ]
            duthost.shell_cmds(cmds=cmds)
    yield
    # Recover DUT by reloading minigraph
    for duthost in duthosts:
        config_reload(duthost, config_source="minigraph")


def get_t2_info(duthosts, tbinfo):
    # Get the list of upstream/downstream ports
    downstream_ports, upstream_ports, acl_table_ports_per_dut = defaultdict(list), defaultdict(list), defaultdict(list)
    upstream_port_id_to_router_mac_map, downstream_port_id_to_router_mac_map = {}, {}
    downstream_port_ids, upstream_port_ids = [], []
    port_channels = dict()

    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        upstream_ports_per_dut, downstream_ports_per_dut, acl_table_ports = (defaultdict(list),
                                                                             defaultdict(list), defaultdict(list))

        for sonic_host_or_asic_inst in duthost.get_sonic_host_and_frontend_asic_instance():
            namespace = sonic_host_or_asic_inst.namespace if hasattr(sonic_host_or_asic_inst, 'namespace') \
                  else DEFAULT_NAMESPACE
            if duthost.sonichost.is_multi_asic and namespace == DEFAULT_NAMESPACE:
                continue
            asic_id = duthost.get_asic_id_from_namespace(namespace)
            router_mac = duthost.asic_instance(asic_id).get_router_mac()
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo, namespace)
            for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
                port_id = mg_facts["minigraph_ptf_indices"][interface]
                if "T1" in neighbor["name"]:
                    downstream_ports_per_dut[namespace].append(interface)
                    downstream_port_ids.append(port_id)
                    downstream_port_id_to_router_mac_map[port_id] = router_mac
                elif "T3" in neighbor["name"]:
                    upstream_ports_per_dut[namespace].append(interface)
                    upstream_port_ids.append(port_id)
                    upstream_port_id_to_router_mac_map[port_id] = router_mac
                mg_facts = duthost.get_extended_minigraph_facts(tbinfo, namespace)

            port_channels[namespace] = mg_facts["minigraph_portchannels"]
            backend_pc = list()
            for k in port_channels[namespace]:
                if duthost.is_backend_portchannel(k, mg_facts):
                    backend_pc.append(k)
            for pc in backend_pc:
                port_channels[namespace].pop(pc)

            upstream_rifs = upstream_ports_per_dut[namespace]
            downstream_rifs = downstream_ports_per_dut[namespace]
            for k, v in list(port_channels[namespace].items()):
                acl_table_ports[namespace].append(k)
                acl_table_ports[''].append(k)
                upstream_rifs = list(set(upstream_rifs) - set(v['members']))
                downstream_rifs = list(set(downstream_rifs) - set(v['members']))
            if len(upstream_rifs):
                for port in upstream_rifs:
                    # This code is commented due to a bug which restricts rif interfaces to
                    # be added to global acl table - https://github.com/sonic-net/sonic-utilities/issues/2185
                    if namespace == DEFAULT_NAMESPACE:
                        acl_table_ports[''].append(port)
                    else:
                        acl_table_ports[namespace].append(port)
            else:
                for port in downstream_rifs:
                    # This code is commented due to a bug which restricts rif interfaces to
                    # be added to global acl table - https://github.com/sonic-net/sonic-utilities/issues/2185
                    if namespace == DEFAULT_NAMESPACE:
                        acl_table_ports[''].append(port)
                    else:
                        acl_table_ports[namespace].append(port)

        acl_table_ports_per_dut[duthost] = acl_table_ports
        downstream_ports[duthost] = downstream_ports_per_dut
        upstream_ports[duthost] = upstream_ports_per_dut

    t2_information = {
        "upstream_port_ids": upstream_port_ids,
        "downstream_port_ids": downstream_port_ids,
        "downstream_port_id_to_router_mac_map": downstream_port_id_to_router_mac_map,
        "upstream_port_id_to_router_mac_map": upstream_port_id_to_router_mac_map,
        "acl_table_ports": acl_table_ports_per_dut
    }

    return t2_information


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

    if topo == "mx":
        DOWNSTREAM_DST_IP = DOWNSTREAM_DST_IP_VLAN
        DOWNSTREAM_IP_TO_ALLOW = DOWNSTREAM_IP_TO_ALLOW_VLAN
        DOWNSTREAM_IP_TO_BLOCK = DOWNSTREAM_IP_TO_BLOCK_VLAN
    # Announce routes for m0 is something different from t1/t0
    if topo_scenario == "m0_vlan_scenario":
        topo = "m0_vlan"
        if tbinfo["topo"]["name"] == "m0-2vlan":
            DOWNSTREAM_DST_IP = DOWNSTREAM_DST_IP_VLAN2000 if vlan_name == "Vlan2000" else DOWNSTREAM_DST_IP_VLAN
            DOWNSTREAM_IP_TO_ALLOW = DOWNSTREAM_IP_TO_ALLOW_VLAN2000 if vlan_name == "Vlan2000" \
                else DOWNSTREAM_IP_TO_ALLOW_VLAN
            DOWNSTREAM_IP_TO_BLOCK = DOWNSTREAM_IP_TO_BLOCK_VLAN2000 if vlan_name == "Vlan2000" \
                else DOWNSTREAM_IP_TO_BLOCK_VLAN
        else:
            DOWNSTREAM_DST_IP = DOWNSTREAM_DST_IP_VLAN
            DOWNSTREAM_IP_TO_ALLOW = DOWNSTREAM_IP_TO_ALLOW_VLAN
            DOWNSTREAM_IP_TO_BLOCK = DOWNSTREAM_IP_TO_BLOCK_VLAN
    elif topo_scenario == "m0_l3_scenario":
        topo = "m0_l3"
        DOWNSTREAM_DST_IP = DOWNSTREAM_DST_IP_M0_L3
        DOWNSTREAM_IP_TO_ALLOW = DOWNSTREAM_IP_TO_ALLOW_M0_L3
        DOWNSTREAM_IP_TO_BLOCK = DOWNSTREAM_IP_TO_BLOCK_M0_L3
    if topo in ["t0", "mx", "m0_vlan"]:
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

    # For M0_VLAN/MX/T0/dual ToR scenario, we need to use the VLAN MAC to interact with downstream ports
    # For T1/M0_L3 scenario, no VLANs are present so using the router MAC is acceptable
    downlink_dst_mac = vlan_mac if vlan_mac is not None else rand_selected_dut.facts["router_mac"]

    if topo == "t2":
        t2_info = get_t2_info(duthosts, tbinfo)
        downstream_port_ids = t2_info['downstream_port_ids']
        upstream_port_ids = t2_info['upstream_port_ids']
        downstream_port_id_to_router_mac_map = t2_info['downstream_port_id_to_router_mac_map']
        upstream_port_id_to_router_mac_map = t2_info['upstream_port_id_to_router_mac_map']
    else:
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

    if topo in ["t0", "mx", "m0_vlan", "m0_l3"] or tbinfo["topo"]["name"] in ("t1", "t1-lag"):
        for namespace, port in list(downstream_ports.items()):
            acl_table_ports[namespace] += port
            # In multi-asic we need config both in host and namespace.
            if namespace:
                acl_table_ports[''] += port

    if topo in ["t0", "m0_vlan", "m0_l3"] or tbinfo["topo"]["name"] in ("t1-lag", "t1-64-lag", "t1-64-lag-clet",
                                                                        "t1-56-lag"):
        for k, v in list(port_channels.items()):
            acl_table_ports[v['namespace']].append(k)
            # In multi-asic we need config both in host and namespace.
            if v['namespace']:
                acl_table_ports[''].append(k)
    elif topo == "t2":
        acl_table_ports = t2_info['acl_table_ports']
    else:
        for namespace, port in list(upstream_ports.items()):
            acl_table_ports[namespace] += port
            # In multi-asic we need config both in host and namespace.
            if namespace:
                acl_table_ports[''] += port

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

    logger.info("Gathered variables for ACL test:\n{}".format(pprint.pformat(setup_information)))

    logger.info("Creating temporary folder \"{}\" for ACL test".format(DUT_TMP_DIR))
    for duthost in duthosts:
        duthost.command("mkdir -p {}".format(DUT_TMP_DIR))

    yield setup_information

    logger.info("Removing temporary directory \"{}\"".format(DUT_TMP_DIR))
    for duthost in duthosts:
        duthost.command("rm -rf {}".format(DUT_TMP_DIR))


@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def ip_version(request, tbinfo, duthosts, rand_one_dut_hostname):
    if tbinfo["topo"]["type"] in ["t0"] and request.param == "ipv6":
        pytest.skip("IPV6 ACL test not currently supported on t0 testbeds")

    return request.param


@pytest.fixture(scope="module")
def populate_vlan_arp_entries(setup, ptfhost, duthosts, rand_one_dut_hostname, ip_version):
    """Set up the ARP responder utility in the PTF container."""
    global DOWNSTREAM_IP_PORT_MAP
    # For m0 topo, need to refresh this constant for two different scenario
    DOWNSTREAM_IP_PORT_MAP = {}
    duthost = duthosts[rand_one_dut_hostname]
    if setup["topo"] not in ["t0", "mx", "m0_vlan"]:
        def noop():
            pass

        yield noop

        return  # Don't fall through to t0/mx/m0_vlan case

    addr_list = [DOWNSTREAM_DST_IP[ip_version], DOWNSTREAM_IP_TO_ALLOW[ip_version], DOWNSTREAM_IP_TO_BLOCK[ip_version]]

    vlan_host_map = defaultdict(dict)
    for i in range(len(addr_list)):
        mac = VLAN_BASE_MAC_PATTERN.format(i)
        port = random.choice(setup["vlan_ports"])
        addr = addr_list[i]
        vlan_host_map[port][str(addr)] = mac
        DOWNSTREAM_IP_PORT_MAP[addr] = port

    arp_responder_conf = {}
    for port in vlan_host_map:
        arp_responder_conf['eth{}'.format(port)] = vlan_host_map[port]

    with open("/tmp/from_t1.json", "w") as ar_config:
        json.dump(arp_responder_conf, ar_config)
    ptfhost.copy(src="/tmp/from_t1.json", dest="/tmp/from_t1.json")

    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": "-e"})
    ptfhost.template(src="templates/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread && supervisorctl update")
    ptfhost.shell("supervisorctl restart arp_responder")

    def populate_arp_table():
        for dut in duthosts:
            dut.command("sonic-clear fdb all")
            dut.command("sonic-clear arp")
            dut.command("sonic-clear ndp")
            # Wait some time to ensure the async call of clear is completed
            time.sleep(20)
            for addr in addr_list:
                dut.command("ping {} -c 3".format(addr), module_ignore_errors=True)

    populate_arp_table()

    yield populate_arp_table

    logging.info("Stopping ARP responder")
    ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)

    duthost.command("sonic-clear fdb all")
    duthost.command("sonic-clear arp")
    duthost.command("sonic-clear ndp")


@pytest.fixture(scope="module", params=["ingress"])#, "egress"])
def stage(request, duthosts, rand_one_dut_hostname, tbinfo):
    """Parametrize tests for Ingress/Egress stage testing.

    Args:
        request: A fixture to interact with Pytest data.
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.

    Returns:
        str: The ACL stage to be tested.

    """
    duthost = duthosts[rand_one_dut_hostname]
    pytest_require(
        request.param == "ingress" or duthost.facts.get("platform_asic") == "broadcom-dnx"
        or duthost.facts["asic_type"] not in ("broadcom"),
        "Egress ACLs are not currently supported on \"{}\" ASICs".format(duthost.facts["asic_type"])
    )

    return request.param

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

@pytest.fixture(scope="module")
def acl_table_type(duthost):
    """Create a new ACL table type that can be used"""
    json_patch = [
        {
            "op": "add", 
            "path": "/ACL_TABLE_TYPE", 
            "value": { 
                "DYNAMIC_ACL_TABLE_TYPE" : { 
                "MATCHES": ["DST_IP","DST_IPV6","IN_PORTS"], 
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
        yield
    finally:
        delete_tmpfile(duthost)

@pytest.fixture(scope="module")
def acl_table(duthost, setup, stage, acl_table_type):
    """Create a new ACL table type that can be used"""
    json_patch = [
        {
            "op": "add", 
            "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE", 
            "value": { 
                "policy_desc": "DYNAMIC_ACL_TABLE", 
                "type": "DYNAMIC_ACL_TABLE_TYPE", 
                "stage": stage, 
                "ports": setup["acl_table_ports"]['']
            }                        
        }
    ]

    expected_bindings = setup["acl_table_ports"]['']
    expected_first_line = ["DYNAMIC_ACL_TABLE", "DYNAMIC_ACL_TABLE_TYPE", setup["acl_table_ports"][''][0], "DYNAMIC_ACL_TABLE", "ingress"]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        expect_acl_table_match_multiple_bindings(duthost, "DYNAMIC_ACL_TABLE", expected_first_line, expected_bindings)
        yield
    finally:
        delete_tmpfile(duthost, tmpfile)


class BaseAclTest(six.with_metaclass(ABCMeta, object)):
    """Base class for testing ACL rules.

    Subclasses must provide `setup_rules` method to prepare ACL rules for traffic testing.

    They can optionally override `teardown_rules`, which will otherwise remove the rules by
    applying an empty configuration file.
    """

    ACL_COUNTERS_UPDATE_INTERVAL_SECS = 10

    @abstractmethod
    def setup_rules(self, dut, acl_table, ip_version):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        pass

    def post_setup_hook(self, dut, localhost, populate_vlan_arp_entries, tbinfo, conn_graph_facts):   # noqa F811
        """Perform actions after rules have been applied.

        Args:
            dut: The DUT having ACLs applied.
            localhost: The host from which tests are run.
            populate_vlan_arp_entries: A function to populate ARP/FDB tables for VLAN interfaces.

        """
        pass

    @pytest.fixture(params=["downlink->uplink", "uplink->downlink"])
    def direction(self, request):
        """Parametrize test based on direction of traffic."""
        return request.param

    @pytest.fixture(autouse=True)
    def get_src_port(self, setup, direction):
        """Get a source port for the current test."""
        src_ports = setup["downstream_port_ids"] if direction == "downlink->uplink" else setup["upstream_port_ids"]
        src_port = random.choice(src_ports)
        logger.info("Selected source port {}".format(src_port))
        self.src_port = src_port

    def get_dst_ports(self, setup, direction):
        """Get the set of possible destination ports for the current test."""
        return setup["upstream_port_ids"] if direction == "downlink->uplink" else setup["downstream_port_ids"]

    def get_dst_ip(self, direction, ip_version):
        """Get the default destination IP for the current test."""
        return UPSTREAM_DST_IP[ip_version] if direction == "downlink->uplink" else DOWNSTREAM_DST_IP[ip_version]

    def tcp_packet(self, setup, direction, ptfadapter, ip_version,
                   src_ip=None, dst_ip=None, proto=None, sport=0x4321, dport=0x51, flags=None):
        """Generate a TCP packet for testing."""
        src_ip = src_ip or DEFAULT_SRC_IP[ip_version]
        dst_ip = dst_ip or self.get_dst_ip(direction, ip_version)
        if ip_version == "ipv4":
            pkt = testutils.simple_tcp_packet(
                eth_dst=setup["destination_mac"][direction][self.src_port],
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
                eth_dst=setup["destination_mac"][direction][self.src_port],
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
    
    @pytest.fixture(scope="class", autouse=True)
    def create_acl_rules(self, duthost):
        self.setup_rules(duthost)
    
    def replace_and_teardown_rules(self, duthost):
        self.dynamic_acl_remove_drop_rule(duthost)
        self.dynamic_acl_replace_nonexistant_rule(duthost)
        self.dynamic_acl_replace_rules(duthost)
        self.dynamic_acl_remove_forward_rules(duthost)
        self.dynamic_acl_remove_nonexistant_table(duthost)
        self.dynamic_acl_remove_table(duthost)
        self.dynamic_acl_remove_table_type(duthost)

    def dynamic_acl_create_forward_rules(duthost):
        """Create forward ACL rules"""

        dst_ipv4 = DOWNSTREAM_IP_TO_ALLOW["ipv4"]+"/32"
        dst_ipv6 = DOWNSTREAM_IP_TO_ALLOW["ipv6"]+"/128"

        json_patch = [ 
            { 
                "op": "add", 
                "path": "/ACL_RULE", 
                "value": { 
                    "DYNAMIC_ACL_TABLE|RULE_1": {
                        "DST_IP": dst_ipv4, 
                        "PRIORITY": "9999", 
                        "PACKET_ACTION": "FORWARD" 
                    }, 
                    "DYNAMIC_ACL_TABLE|RULE_2": {
                        "DST_IPV6": dst_ipv6, 
                        "PRIORITY": "9998", 
                        "PACKET_ACTION": "FORWARD" 
                    }
                }                                                                                                                               
            } 
        ] 

        expected_rule_1_content = ["DYNAMIC_ACL_TABLE", "RULE_1", "9999", "FORWARD", "DST_IP:", dst_ipv4]
        expected_rule_2_content = ["DYNAMIC_ACL_TABLE", "RULE_2", "9998", "FORWARD", "DST_IPV6:",  dst_ipv6]

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

    def dynamic_acl_verify_packets(self, setup, direction, ptfadapter, ip_version, packets_dropped):

        if packets_dropped:
            pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version)
            self._verify_acl_traffic(setup, direction, ptfadapter, pkt, True, ip_version)
        else:
            dst_ip = dst_ip = DOWNSTREAM_IP_TO_ALLOW[ip_version] 
            pkt = self.tcp_packet(setup, direction, ptfadapter, ip_version, dst_ip=dst_ip)
            self._verify_acl_traffic(setup, direction, ptfadapter, pkt, False, ip_version)

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
    
    def test_dynamic_acl(self, rand_selected_dut, setup, direction, ptfadapter, ip_version, stage, acl_table):
        """Test all dynamic ACL functionality"""

        
        self.dynamic_acl_verify_packets(setup, direction, ptfadapter, ip_version, packets_dropped = True) #Verify that packets not forwarded are universally dropped
        self.dynamic_acl_verify_packets(setup, direction, ptfadapter, ip_version, packets_dropped = False) #Verify that packets are correctly forwarded
        
        self.replace_and_teardown_rules(rand_selected_dut)


class TestBasicAcl(BaseAclTest):
    """Test Basic functionality of ACL rules (i.e. setup with full update on a running device)."""

    def setup_rules(self, dut, acl_table, ip_version):
        """Setup ACL rules for testing.

        Args:
            dut: The DUT having ACLs applied.
            acl_table: Configuration info for the ACL table.

        """
        self.dynamic_acl_create_forward_rules(dut)
        self.dynamic_acl_create_drop_rule(dut)
