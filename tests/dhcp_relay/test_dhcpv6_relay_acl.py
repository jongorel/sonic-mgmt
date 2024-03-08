import ipaddress
import pytest
import time
import netaddr
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.utilities import skip_release
from tests.ptf_runner import ptf_runner
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m  # noqa F401

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload

CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json.before_gcu_test"

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx'),
    pytest.mark.device_type('vs')
]

SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'
NEW_COUNTER_VALUE_FORMAT = (
    "{'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0','Confirm':'0','Renew':'0','Rebind':'0','Reply':'0',"
    "'Release':'0','Decline':'0','Reconfigure':'0','Information-Request':'0','Relay-Forward':'0','Relay-Reply':'0',"
    "'Malformed':'0'}"
)

dhcp_patch = [
    {
        "op": "add",
        "path": "/ACL_RULE",
        "value": {
            "DYNAMIC_ACL_TABLE|DHCPV6_RULE": {
                "IP_PROTOCOL": "17",
                "DST_IPV6": "ff02::1:2/128",
                "PRIORITY": "9998",
                "PACKET_ACTION": "FORWARD"
            }
        }
    }
]

custom_type_patch = [
    {
        "op": "add",
        "path": "/ACL_TABLE_TYPE",
        "value": {
            "DYNAMIC_ACL_TABLE_TYPE" : {
            "MATCHES": ["DST_IP","DST_IPV6","ETHER_TYPE","IN_PORTS","L4_DST_PORT","IP_PROTOCOL","IP_TYPE"],
            "ACTIONS": ["PACKET_ACTION","COUNTER"],
            "BIND_POINTS": ["PORT"]
            }
        }
    }
]

custom_table_patch = []

drop_rule_patch = []

# Module Fixture
@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    """
    Config facts for selected DUT
    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: Hostname of a random chosen dut
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthosts, rand_one_dut_hostname):
    """Skips this test if the SONiC image installed on DUT is older than 202111

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: Hostname of a random chosen dut

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])


@pytest.fixture(scope="module", autouse=True)
def reset_and_restore_test_environment(duthosts, rand_one_dut_hostname):
    """Reset and restore test env if initial Config cannot pass Yang

    Back up the existing config_db.json file and restore it once the test ends.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: Hostname of a random chosen dut

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    json_patch = []
    tmpfile = generate_tmpfile(duthost)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    logger.info("Backup {} to {} on {}".format(
        CONFIG_DB, CONFIG_DB_BACKUP, duthost.hostname))
    duthost.shell("cp {} {}".format(CONFIG_DB, CONFIG_DB_BACKUP))

    if output['rc'] or "Patch applied successfully" not in output['stdout']:
        logger.info("Running config failed SONiC Yang validation. Reload minigraph. config: {}"
                    .format(output['stdout']))
        config_reload(duthost, config_source="minigraph", safe_reload=True)

    yield

    logger.info("Restore {} with {} on {}".format(
        CONFIG_DB, CONFIG_DB_BACKUP, duthost.hostname))
    duthost.shell("mv {} {}".format(CONFIG_DB_BACKUP, CONFIG_DB))

    if output['rc'] or "Patch applied successfully" not in output['stdout']:
        logger.info("Restore Config after GCU test.")
        config_reload(duthost)


@pytest.fixture(scope="module", autouse=True)
def verify_configdb_with_empty_input(duthosts, rand_one_dut_hostname):
    """Fail immediately if empty input test failure

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: Hostname of a random chosen dut

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]
    json_patch = []
    tmpfile = generate_tmpfile(duthost)

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if output['rc'] or "Patch applied successfully" not in output['stdout']:
            pytest.fail(
                "SETUP FAILURE: ConfigDB fail to validate Yang. rc:{} msg:{}"
                .format(output['rc'], output['stdout'])
            )

    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.fixture(scope='function')
def skip_when_buffer_is_dynamic_model(duthost):
    buffer_model = duthost.shell(
        'redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model')['stdout']
    if buffer_model == 'dynamic':
        pytest.skip("Skip the test, because dynamic buffer config cannot be updated")


# Function Fixture
@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    """
       Ignore expected yang validation failure during test execution

       GCU will try several sortings of JsonPatch until the sorting passes yang validation

       Args:
            duthosts: list of DUTs.
            rand_one_dut_hostname: Hostname of a random chosen dut
           loganalyzer: Loganalyzer utility fixture
    """
    # When loganalyzer is disabled, the object could be None
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:
        ignoreRegex = [
            ".*ERR sonic_yang.*",
            ".*ERR.*Failed to start dhcp_relay.service - dhcp_relay container.*",  # Valid test_dhcp_relay for Bookworm
            ".*ERR.*Failed to start dhcp_relay container.*",  # Valid test_dhcp_relay
            # Valid test_dhcp_relay test_syslog
            ".*ERR GenericConfigUpdater: Service Validator: Service has been reset.*",
            ".*ERR teamd[0-9].*get_dump: Can't get dump for LAG.*",  # Valid test_portchannel_interface
            ".*ERR swss[0-9]*#intfmgrd: :- setIntfVrf:.*",  # Valid test_portchannel_interface
            ".*ERR swss[0-9]*#orchagent.*removeLag.*",  # Valid test_portchannel_interface
            ".*ERR kernel.*Reset adapter.*",  # Valid test_portchannel_interface replace mtu
            ".*ERR swss[0-9]*#orchagent: :- getPortOperSpeed.*",  # Valid test_portchannel_interface replace mtu
            ".*ERR systemd.*Failed to start Host core file uploader daemon.*",  # Valid test_syslog

            # sonic-swss/orchagent/crmorch.cpp
            ".*ERR swss[0-9]*#orchagent.*getResAvailableCounters.*",  # test_monitor_config
            ".*ERR swss[0-9]*#orchagent.*objectTypeGetAvailability.*",  # test_monitor_config
            ".*ERR dhcp_relay[0-9]*#dhcrelay.*",  # test_dhcp_relay

            # sonic-sairedis/vslib/HostInterfaceInfo.cpp: Need investigation
            ".*ERR syncd[0-9]*#syncd.*tap2veth_fun: failed to write to socket.*",   # test_portchannel_interface tc2
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

logger = logging.getLogger(__name__)


def wait_all_bgp_up(duthost):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    if not wait_until(180, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())):
        pytest.fail("not all bgp sessions are up after config change")


def check_dhcpv6_relay_counter(duthost, ifname, type, dir):
    # new counter table
    # sonic-db-cli STATE_DB hgetall 'DHCPv6_COUNTER_TABLE|Vlan1000'
    # {'TX': "{'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0','Confirm':'0','Renew':'0','Rebind':'0',
    #  'Reply':'0', 'Release':'0','Decline':'0','Reconfigure':'0','Information-Request':'0','Relay-Forward':'0',
    #  'Relay-Reply':'0','Malformed':'0'}", 'RX': "{'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0',
    #  'Confirm':'0','Renew':'0','Rebind':'0','Reply':'0', 'Release':'0','Decline':'0','Reconfigure':'0',
    #  'Information-Request':'0','Relay-Forward':'0','Relay-Reply':'0','Malformed':'0'}"}
    #
    # old counter table
    # sonic-db-cli STATE_DB hgetall 'DHCPv6_COUNTER_TABLE|Vlan1000'
    # {'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0','Confirm':'0','Renew':'0','Rebind':'0','Reply':'0',
    #  'Release':'0','Decline':'0','Reconfigure':'0','Information-Request':'0','Relay-Forward':'0','Relay-Reply':'0',
    #  'Malformed':'0'}
    #
    cmd_new_version = 'sonic-db-cli STATE_DB hget "DHCPv6_COUNTER_TABLE|{}" {}'.format(ifname, dir)
    cmd_old_version = 'sonic-db-cli STATE_DB hget "DHCPv6_COUNTER_TABLE|{}" {}'.format(ifname, type)
    output_new = duthost.shell(cmd_new_version)['stdout']
    if len(output_new) != 0:
        counters = eval(output_new)
        assert int(counters[type]) > 0, "{}({}) missing {} count".format(ifname, dir, type)
    else:
        # old version only support vlan couting
        if 'Vlan' not in ifname:
            return
        output_old = duthost.shell(cmd_old_version)['stdout']
        assert int(output_old) > 0, "{} missing {} count".format(ifname, type)


def init_counter(duthost, ifname, types):
    cmd_new_version = 'sonic-db-cli STATE_DB hget "DHCPv6_COUNTER_TABLE|{}" RX'.format(ifname)
    output_new = duthost.shell(cmd_new_version)['stdout']
    if len(output_new) != 0:
        counters_str = NEW_COUNTER_VALUE_FORMAT
        cmd = 'sonic-db-cli STATE_DB hmset "DHCPv6_COUNTER_TABLE|{}" "RX" "{}"'.format(ifname, str(counters_str))
        duthost.shell(cmd)
        cmd = 'sonic-db-cli STATE_DB hmset "DHCPv6_COUNTER_TABLE|{}" "TX" "{}"'.format(ifname, str(counters_str))
        duthost.shell(cmd)
    else:
        for type in types:
            cmd = 'sonic-db-cli STATE_DB hmset "DHCPv6_COUNTER_TABLE|{}" {} 0'.format(ifname, type)
            duthost.shell(cmd)


@pytest.fixture(scope="module")
def testing_config(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    subtype_exist, subtype_value = get_subtype_from_configdb(duthost)

    if 'dualtor' in tbinfo['topo']['name']:
        if not subtype_exist or subtype_value != 'DualToR':
            assert False, "Wrong DHCP setup on Dual ToR testbeds"
        yield DUAL_TOR_MODE, duthost
    else:
        yield SINGLE_TOR_MODE, duthost


def get_subtype_from_configdb(duthost):
    # HEXISTS returns 1 if the key exists, otherwise 0
    subtype_exist = int(duthost.shell('redis-cli -n 4 HEXISTS "DEVICE_METADATA|localhost" "subtype"')["stdout"])
    subtype_value = ""
    if subtype_exist:
        subtype_value = duthost.shell('redis-cli -n 4 HGET "DEVICE_METADATA|localhost" "subtype"')["stdout"]
    return subtype_exist, subtype_value


@pytest.fixture(scope="module")
def dut_dhcp_relay_data(duthosts, rand_one_dut_hostname, tbinfo):
    """ Fixture which returns a list of dictionaries where each dictionary contains
        data necessary to test one instance of a DHCP relay agent running on the DuT.
        This fixture is scoped to the module, as the data it gathers can be used by
        all tests in this module. It does not need to be run before each test.
    """

    global drop_rule_patch, custom_table_patch

    duthost = duthosts[rand_one_dut_hostname]
    dhcp_relay_data_list = []
    down_interface_link_local = ""

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # SONiC spawns one DHCP relay agent per VLAN interface configured on the DUT
    vlan_dict = mg_facts['minigraph_vlans']
    for vlan_iface_name, vlan_info_dict in list(vlan_dict.items()):
        # Filter(remove) PortChannel interfaces from VLAN members list
        vlan_members = [port for port in vlan_info_dict['members'] if 'PortChannel' not in port]
        if not vlan_members:
            continue

        # Gather information about the downlink VLAN interface this relay agent is listening on
        downlink_vlan_iface = {}
        downlink_vlan_iface['name'] = vlan_iface_name

        for vlan_interface_info_dict in mg_facts['minigraph_vlan_interfaces']:
            if (vlan_interface_info_dict['attachto'] == vlan_iface_name) and \
               (netaddr.IPAddress(str(vlan_interface_info_dict['addr'])).version == 6):
                downlink_vlan_iface['addr'] = vlan_interface_info_dict['addr']
                downlink_vlan_iface['mask'] = vlan_interface_info_dict['mask']
                break

        # Obtain MAC address of the VLAN interface
        res = duthost.shell('cat /sys/class/net/{}/address'.format(vlan_iface_name))
        downlink_vlan_iface['mac'] = res['stdout']

        downlink_vlan_iface['dhcpv6_server_addrs'] = mg_facts['dhcpv6_servers']

        # We choose the physical interface where our DHCP client resides to be index of first interface in the VLAN
        client_iface = {}
        client_iface['name'] = vlan_members[0]
        client_iface['alias'] = mg_facts['minigraph_port_name_to_alias_map'][client_iface['name']]
        client_iface['port_idx'] = mg_facts['minigraph_ptf_indices'][client_iface['name']]

        custom_table_patch = [
            {
                "op": "add",
                "path": "/ACL_TABLE/DYNAMIC_ACL_TABLE",
                "value": {
                    "policy_desc": "DYNAMIC_ACL_TABLE",
                    "type": "DYNAMIC_ACL_TABLE_TYPE",
                    "stage": "INGRESS",
                    "ports": [client_iface['name']]
                }
            }
        ]

        drop_rule_patch = [
            {
                "op": "add",
                "path": "/ACL_RULE/DYNAMIC_ACL_TABLE|RULE_3",
                "value": {
                    "PRIORITY": "9996",
                    "PACKET_ACTION": "DROP",
                    "IN_PORTS": client_iface['name']
                }
            }
        ]

        # Obtain uplink port indicies for this DHCP relay agent
        uplink_interfaces = []
        uplink_port_indices = []
        topo_type = tbinfo['topo']['type']
        for iface_name, neighbor_info_dict in list(mg_facts['minigraph_neighbors'].items()):
            if neighbor_info_dict['name'] in mg_facts['minigraph_devices']:
                neighbor_device_info_dict = mg_facts['minigraph_devices'][neighbor_info_dict['name']]
                if 'type' not in neighbor_device_info_dict:
                    continue
                nei_type = neighbor_device_info_dict['type']
                if topo_type == 't0' and nei_type == 'LeafRouter' or \
                   topo_type == 'm0' and nei_type == 'MgmtLeafRouter' or \
                   topo_type == 'mx' and nei_type == 'MgmtToRRouter':
                    # If this uplink's physical interface is a member of a portchannel interface,
                    # we record the name of the portchannel interface here, as this is the actual
                    # interface the DHCP relay will listen on.
                    iface_is_portchannel_member = False
                    for portchannel_name, portchannel_info_dict in list(mg_facts['minigraph_portchannels'].items()):
                        if 'members' in portchannel_info_dict and iface_name in portchannel_info_dict['members']:
                            iface_is_portchannel_member = True
                            if portchannel_name not in uplink_interfaces:
                                uplink_interfaces.append(portchannel_name)
                            break
                    # If the uplink's physical interface is not a member of a portchannel,
                    # add it to our uplink interfaces list
                    if not iface_is_portchannel_member:
                        uplink_interfaces.append(iface_name)
                    uplink_port_indices.append(mg_facts['minigraph_ptf_indices'][iface_name])
        if down_interface_link_local == "":
            command = "ip addr show {} | grep inet6 | grep 'scope link' | awk '{{print $2}}' | cut -d '/' -f1"\
                      .format(downlink_vlan_iface['name'])
            res = duthost.shell(command)
            if res['stdout'] != "":
                down_interface_link_local = res['stdout']

        dhcp_relay_data = {}
        dhcp_relay_data['downlink_vlan_iface'] = downlink_vlan_iface
        dhcp_relay_data['client_iface'] = client_iface
        dhcp_relay_data['uplink_interfaces'] = uplink_interfaces
        dhcp_relay_data['uplink_port_indices'] = uplink_port_indices
        dhcp_relay_data['down_interface_link_local'] = down_interface_link_local
        dhcp_relay_data['loopback_iface'] = mg_facts['minigraph_lo_interfaces']
        dhcp_relay_data['loopback_ipv6'] = mg_facts['minigraph_lo_interfaces'][1]['addr']
        if 'dualtor' in tbinfo['topo']['name']:
            dhcp_relay_data['is_dualtor'] = True
        else:
            dhcp_relay_data['is_dualtor'] = False

        res = duthost.shell('cat /sys/class/net/{}/address'.format(uplink_interfaces[0]))
        dhcp_relay_data['uplink_mac'] = res['stdout']

        dhcp_relay_data_list.append(dhcp_relay_data)

    return dhcp_relay_data_list


@pytest.fixture(scope="module")
def validate_dut_routes_exist(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data):
    """Fixture to valid a route to each DHCP server exist
    """
    duthost = duthosts[rand_one_dut_hostname]
    dhcp_servers = set()
    for dhcp_relay in dut_dhcp_relay_data:
        dhcp_servers |= set(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs'])

    for dhcp_server in dhcp_servers:
        rtInfo = duthost.get_ip_route_info(ipaddress.ip_address(dhcp_server))
        assert len(rtInfo["nexthops"]) > 0, "Failed to find route to DHCP server '{0}'".format(dhcp_server)


def check_interface_status(duthost):
    if ":547" in duthost.shell("docker exec -t dhcp_relay ss -nlp | grep dhcp6relay")["stdout"]:
        return True
    return False


def test_dhcp_relay_default(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            toggle_all_simulator_ports_to_rand_selected_tor_m):  # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """
    _, duthost = testing_config

    create_checkpoint(duthost)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=custom_type_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    expect_op_success(duthost, output)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=custom_table_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    expect_op_success(duthost, output)

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=dhcp_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    expect_op_success(duthost, output)

    output = duthost.show_and_parse("show acl rule DYNAMIC_ACL_TABLE DHCPV6_RULE")

    first_line = output[0].values()

    pytest_assert("Active" in set(first_line), str(first_line) + " does not contain Active!")

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=drop_rule_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    expect_op_success(duthost, output)

    skip_release(duthost, ["201811", "201911", "202106"])  # TO-DO: delete skip release on 201811 and 201911

    # Please note: relay interface always means vlan interface
    for dhcp_relay in dut_dhcp_relay_data:
        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcpv6_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']),
                           "server_ip": str(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs'][0]),
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_link_local": str(dhcp_relay['down_interface_link_local']),
                           "vlan_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "loopback_ipv6": str(dhcp_relay['loopback_ipv6']),
                           "is_dualtor": str(dhcp_relay['is_dualtor'])},
                   log_file="/tmp/dhcpv6_relay_test.DHCPTest.log", is_python3=True)

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)

