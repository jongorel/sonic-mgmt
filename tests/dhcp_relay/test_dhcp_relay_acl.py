import ipaddress
import pytest
import random
import time
import logging
import re

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import check_link_status
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload


CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json.before_gcu_test"


pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs')
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'

dhcp_patch = [
    {
        "op": "add",
        "path": "/ACL_RULE",
        "value": {
            "DYNAMIC_ACL_TABLE|DHCP_RULE": {
                "IP_PROTOCOL": "17",
                "L4_DST_PORT": "67",
                "ETHER_TYPE": "0x0800",
                "PRIORITY": "9999",
                "PACKET_ACTION": "FORWARD"
            },
            "DYNAMIC_ACL_TABLE|DHCPV6_RULE": {
                "IP_PROTOCOL": "17",
                "L4_DST_PORT": "547",
                "ETHER_TYPE": "0x86DD",
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


@pytest.fixture(scope="module", autouse=True)
def check_dhcp_server_enabled(duthost):
    feature_status_output = duthost.show_and_parse("show feature status")
    for feature in feature_status_output:
        if feature["feature"] == "dhcp_server" and feature["state"] == "enabled":
            pytest.skip("DHCPv4 relay is not supported when dhcp_server is enabled")


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        ignoreRegex = [
            r".*ERR snmp#snmp-subagent.*",
            r".*ERR rsyslogd: omfwd: socket (\d+): error (\d+) sending via udp: Network is (unreachable|down).*",
            r".*ERR rsyslogd: omfwd/udp: socket (\d+): sendto\(\) error: Network is (unreachable|down).*"
        ]
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(ignoreRegex)

    yield


@pytest.fixture(scope="module")
def dut_dhcp_relay_data(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    """ Fixture which returns a list of dictionaries where each dictionary contains
        data necessary to test one instance of a DHCP relay agent running on the DuT.
        This fixture is scoped to the module, as the data it gathers can be used by
        all tests in this module. It does not need to be run before each test.
    """

    global custom_table_patch, drop_rule_patch

    duthost = duthosts[rand_one_dut_hostname]
    dhcp_relay_data_list = []

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    switch_loopback_ip = mg_facts['minigraph_lo_interfaces'][0]['addr']

    # SONiC spawns one DHCP relay agent per VLAN interface configured on the DUT
    vlan_dict = mg_facts['minigraph_vlans']
    for vlan_iface_name, vlan_info_dict in list(vlan_dict.items()):
        # Filter(remove) PortChannel interfaces from VLAN members list
        vlan_members = [port for port in vlan_info_dict['members'] if 'PortChannel' not in port]

        # Gather information about the downlink VLAN interface this relay agent is listening on
        downlink_vlan_iface = {}
        downlink_vlan_iface['name'] = vlan_iface_name

        for vlan_interface_info_dict in mg_facts['minigraph_vlan_interfaces']:
            if vlan_interface_info_dict['attachto'] == vlan_iface_name:
                downlink_vlan_iface['addr'] = vlan_interface_info_dict['addr']
                downlink_vlan_iface['mask'] = vlan_interface_info_dict['mask']
                break

        # Obtain MAC address of the VLAN interface
        res = duthost.shell('cat /sys/class/net/{}/address'.format(vlan_iface_name))
        downlink_vlan_iface['mac'] = res['stdout']

        downlink_vlan_iface['dhcp_server_addrs'] = mg_facts['dhcp_servers']

        # We choose the physical interface where our DHCP client resides to be index of first interface
        # with alias (ignore PortChannel) in the VLAN
        client_iface = {}
        for port in vlan_members:
            if port in mg_facts['minigraph_port_name_to_alias_map']:
                break
        else:
            continue
        client_iface['name'] = port
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
                    "ports": client_iface['name']
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
        for iface_name, neighbor_info_dict in list(mg_facts['minigraph_neighbors'].items()):
            if neighbor_info_dict['name'] in mg_facts['minigraph_devices']:
                neighbor_device_info_dict = mg_facts['minigraph_devices'][neighbor_info_dict['name']]
                if 'type' in neighbor_device_info_dict and neighbor_device_info_dict['type'] in \
                        ['LeafRouter', 'MgmtLeafRouter']:
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

        other_client_ports_indices = []
        for iface_name in vlan_members:
            if mg_facts['minigraph_ptf_indices'][iface_name] == client_iface['port_idx']:
                pass
            else:
                other_client_ports_indices.append(mg_facts['minigraph_ptf_indices'][iface_name])

        dhcp_relay_data = {}
        dhcp_relay_data['downlink_vlan_iface'] = downlink_vlan_iface
        dhcp_relay_data['client_iface'] = client_iface
        dhcp_relay_data['other_client_ports'] = other_client_ports_indices
        dhcp_relay_data['uplink_interfaces'] = uplink_interfaces
        dhcp_relay_data['uplink_port_indices'] = uplink_port_indices
        dhcp_relay_data['switch_loopback_ip'] = str(switch_loopback_ip)

        # Obtain MAC address of an uplink interface because vlan mac may be different than that of physical interfaces
        res = duthost.shell('cat /sys/class/net/{}/address'.format(uplink_interfaces[0]))
        dhcp_relay_data['uplink_mac'] = res['stdout']
        dhcp_relay_data['default_gw_ip'] = mg_facts['minigraph_mgmt_interface']['gwaddr']

        dhcp_relay_data_list.append(dhcp_relay_data)

    return dhcp_relay_data_list


def check_routes_to_dhcp_server(duthost, dut_dhcp_relay_data):
    """Validate there is route on DUT to each DHCP server
    """
    default_gw_ip = dut_dhcp_relay_data[0]['default_gw_ip']
    dhcp_servers = set()
    for dhcp_relay in dut_dhcp_relay_data:
        dhcp_servers |= set(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])

    for dhcp_server in dhcp_servers:
        rtInfo = duthost.get_ip_route_info(ipaddress.ip_address(dhcp_server))
        nexthops = rtInfo["nexthops"]
        if len(nexthops) == 0:
            logger.info("Failed to find route to DHCP server '{0}'".format(dhcp_server))
            return False
        if len(nexthops) == 1:
            # if only 1 route to dst available - check that it's not default route via MGMT iface
            route_index_in_list = 0
            ip_dst_index = 0
            route_dst_ip = nexthops[route_index_in_list][ip_dst_index]
            if route_dst_ip == ipaddress.ip_address(default_gw_ip):
                logger.info("Found route to DHCP server via default GW(MGMT interface)")
                return False
    return True


@pytest.fixture(scope="module")
def validate_dut_routes_exist(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data):
    """Fixture to valid a route to each DHCP server exist
    """
    pytest_assert(check_routes_to_dhcp_server(duthosts[rand_one_dut_hostname], dut_dhcp_relay_data),
                  "Failed to find route for DHCP server")


def restart_dhcp_service(duthost):
    duthost.shell('systemctl reset-failed dhcp_relay')
    duthost.shell('systemctl restart dhcp_relay')
    duthost.shell('systemctl reset-failed dhcp_relay')

    for retry in range(5):
        time.sleep(30)
        dhcp_status = duthost.shell('docker container top dhcp_relay | grep dhcrelay | cat')["stdout"]
        if dhcp_status != "":
            break
    else:
        assert False, "Failed to restart dhcp docker"

    time.sleep(30)


def get_subtype_from_configdb(duthost):
    # HEXISTS returns 1 if the key exists, otherwise 0
    subtype_exist = int(duthost.shell('redis-cli -n 4 HEXISTS "DEVICE_METADATA|localhost" "subtype"')["stdout"])
    subtype_value = ""
    if subtype_exist:
        subtype_value = duthost.shell('redis-cli -n 4 HGET "DEVICE_METADATA|localhost" "subtype"')["stdout"]
    return subtype_exist, subtype_value


@pytest.fixture(scope="module", params=[SINGLE_TOR_MODE, DUAL_TOR_MODE])
def testing_config(request, duthosts, rand_one_dut_hostname, tbinfo):
    testing_mode = request.param
    duthost = duthosts[rand_one_dut_hostname]
    subtype_exist, subtype_value = get_subtype_from_configdb(duthost)

    if 'dualtor' in tbinfo['topo']['name']:
        if testing_mode == SINGLE_TOR_MODE:
            pytest.skip("skip SINGLE_TOR_MODE tests on Dual ToR testbeds")

        if testing_mode == DUAL_TOR_MODE:
            if not subtype_exist or subtype_value != 'DualToR':
                assert False, "Wrong DHCP setup on Dual ToR testbeds"

            yield testing_mode, duthost, 'dual_testbed'
    elif tbinfo['topo']['name'] in ('t0-54-po2vlan', 't0-56-po2vlan'):
        if testing_mode == SINGLE_TOR_MODE:
            if subtype_exist and subtype_value == 'DualToR':
                assert False, "Wrong DHCP setup on po2vlan testbeds"

            yield testing_mode, duthost, 'single_testbed'

        if testing_mode == DUAL_TOR_MODE:
            pytest.skip("skip DUAL_TOR_MODE tests on po2vlan testbeds")
    else:
        if testing_mode == DUAL_TOR_MODE:
            pytest.skip("skip DUAL_TOR_MODE tests on Single ToR testbeds")

        if testing_mode == SINGLE_TOR_MODE:
            if subtype_exist:
                duthost.shell('redis-cli -n 4 HDEL "DEVICE_METADATA|localhost" "subtype"')
                restart_dhcp_service(duthost)

        if testing_mode == DUAL_TOR_MODE:
            if not subtype_exist or subtype_value != 'DualToR':
                duthost.shell('redis-cli -n 4 HSET "DEVICE_METADATA|localhost" "subtype" "DualToR"')
                restart_dhcp_service(duthost)

        yield testing_mode, duthost, 'single_testbed'

        if testing_mode == DUAL_TOR_MODE:
            duthost.shell('redis-cli -n 4 HDEL "DEVICE_METADATA|localhost" "subtype"')
            restart_dhcp_service(duthost)


def check_interface_status(duthost):
    if ":67" in duthost.shell("docker exec -t dhcp_relay ss -nlp | grep dhcrelay",
                              module_ignore_errors=True)["stdout"]:
        return True

    return False


def start_dhcp_monitor_debug_counter(duthost):
    program_name = "dhcpmon"
    program_pid_list = []
    program_list = duthost.shell("ps aux | grep {}".format(program_name))
    matches = re.findall(r'/usr/sbin/dhcpmon.*', program_list["stdout"])

    for program_info in program_list["stdout_lines"]:
        if program_name in program_info:
            program_pid = int(program_info.split()[1])
            program_pid_list.append(program_pid)

    for program_pid in program_pid_list:
        kill_cmd_result = duthost.shell("sudo kill {} || true".format(program_pid), module_ignore_errors=True)
        # Get the exit code of 'kill' command
        exit_code = kill_cmd_result["rc"]
        if exit_code != 0:
            stderr = kill_cmd_result.get("stderr", "")
            if "No such process" not in stderr:
                pytest.fail("Failed to stop program '{}' before test. Error: {}".format(program_name, stderr))

    if matches:
        for dhcpmon_cmd in matches:
            if "-D" not in dhcpmon_cmd:
                dhcpmon_cmd += " -D"
            duthost.shell("docker exec -d dhcp_relay %s" % dhcpmon_cmd)
    else:
        assert False, "Failed to start dhcpmon in debug counter mode\n"


def test_dhcp_relay_default(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m):     # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """

    testing_mode, duthost, testbed_mode = testing_config

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

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=drop_rule_patch, dest_file=tmpfile)
    finally:
        delete_tmpfile(duthost, tmpfile)

    expect_op_success(duthost, output)

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    skip_dhcpmon = any(vers in duthost.os_version for vers in ["201811", "201911", "202111"])

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            if not skip_dhcpmon:
                dhcp_server_num = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                if testing_mode == DUAL_TOR_MODE:
                    standby_duthost = rand_unselected_dut
                    start_dhcp_monitor_debug_counter(standby_duthost)
                    expected_standby_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +0/ +0, Offer: +0/ +0, Request: +0/ +0, ACK: +0/ +0+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'])
                    loganalyzer_standby = LogAnalyzer(ansible_host=standby_duthost, marker_prefix="dhcpmon counter")
                    marker_standby = loganalyzer_standby.init()
                    loganalyzer_standby.expect_regex = [expected_standby_agg_counter_message]
                start_dhcp_monitor_debug_counter(duthost)
                expected_agg_counter_message = (
                    r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                    r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                    r"Discover: +1/ +%d, Offer: +1/ +1, Request: +3/ +%d, ACK: +1/ +1+"
                ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num * 3)
                loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dhcpmon counter")
                marker = loganalyzer.init()
                loganalyzer.expect_regex = [expected_agg_counter_message]

            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPTest",
                       platform_dir="ptftests",
                       params={"hostname": duthost.hostname,
                               "client_port_index": dhcp_relay['client_iface']['port_idx'],
                               # This port is introduced to test DHCP relay packet received
                               # on other client port
                               "other_client_port": repr(dhcp_relay['other_client_ports']),
                               "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                               "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                               "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                               "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                               "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                               "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                               "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                               "dest_mac_address": BROADCAST_MAC,
                               "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                               "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                               "uplink_mac": str(dhcp_relay['uplink_mac']),
                               "testbed_mode": testbed_mode,
                               "testing_mode": testing_mode},
                       log_file="/tmp/dhcp_relay_test.DHCPTest.log", is_python3=True)
            if not skip_dhcpmon:
                time.sleep(18)      # dhcpmon debug counter prints every 18 seconds
                loganalyzer.analyze(marker)
                if testing_mode == DUAL_TOR_MODE:
                    loganalyzer_standby.analyze(marker_standby)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    if not skip_dhcpmon:
        # Clean up - Restart DHCP relay service on DUT to recover original dhcpmon setting
        restart_dhcp_service(duthost)
        if testing_mode == DUAL_TOR_MODE:
            restart_dhcp_service(standby_duthost)
            pytest_assert(wait_until(120, 5, 0, check_interface_status, standby_duthost))
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost))

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)