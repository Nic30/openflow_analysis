"""
Simple utility which generate a ovs-vsctl add-br command from faucet yaml
"""
import yaml
import sys


def cmd_faucet_yaml_to_ovs_vsctl(yaml_file_name):
    with open(yaml_file_name) as f:
        data = yaml.load(f)

    buff = []
    dps = data['dps']
    for switch_name, switch_config in dps.items():
        switch_id = switch_config['dp_id']
        buff.append(f"""\
ovs-vsctl add-br {switch_name} \\
         -- set bridge {switch_name} other-config:datapath-id={switch_id} \\""")
        for port_id, port_config in switch_config["interfaces"].items():
            port_name = port_config.get("name", f"p{port_id}")
            buff.append(f"         -- add-port {switch_name} {port_name} -- set interface {port_name} ofport_request={port_id} \\")

        buff.append(f"""         -- set-controller {switch_name} tcp:127.0.0.1:6653 \\
         -- set controller {switch_name} connection-mode=out-of-band
        """)
    return "\n".join(buff)


def cmd_create_linux_port(yaml_file_name):
    # Run command inside network namespace
    buff = ["""\
# Run command inside network namespace
as_ns () {
    NETNS=$1
    shift
    sudo ip netns exec ${NETNS} $@
}
# Create network namespace
create_ns () {
    NETNS=$1
    NAME=$2
    IP=$3
    sudo ip netns add ${NETNS}
    sudo ip link add dev ${NAME} type veth peer name veth0 netns ${NETNS}
    sudo ip link set dev ${NAME} up
    as_ns ${NETNS} ip link set dev lo up
    [ -n "${IP}" ] && as_ns ${NETNS} ip addr add dev veth0 ${IP}
    as_ns ${NETNS} ip link set dev veth0 up
}
"""]
    with open(yaml_file_name) as f:
        data = yaml.load(f)

    dps = data['dps']
    switch_i = 0
    net_names = []
    for switch_config in dps.values():
        for port_id, port_config in switch_config["interfaces"].items():
            port_name = port_config.get("name", f"p{port_id}")
            net_name = f"faucet-{switch_i}-{port_name}"
            buff.append(f"create_ns {net_name} {port_name} 192.168.{switch_i}.{port_id}/24")
            net_names.append(net_name)

        switch_i += 1
    buff.append("delete_all_faucet_nets() {")
    for net_name in net_names:
        buff.append(f"    ip netns del {net_name}")
    buff.append("}")

    return "\n".join(buff)


if __name__ == "__main__":
    if sys.argv:
        file_name = "data/faucet_default.yaml"
    else:
        assert len(sys.argv) == 1
        file_name = sys.argv[0]

    print(cmd_create_linux_port(file_name))
    print(cmd_faucet_yaml_to_ovs_vsctl(file_name))

