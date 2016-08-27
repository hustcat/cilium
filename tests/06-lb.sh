#!/bin/bash

source "./helpers.bash"

set -e

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"

function cleanup {
	docker rm -f server1 server2 client 2> /dev/null || true
	monitor_stop
}

trap cleanup EXIT

monitor_start

docker network inspect $TEST_NET 2> /dev/null || {
	docker network create --ipam-driver cilium --driver cilium $TEST_NET
}

docker run -dt --net=$TEST_NET --name server1 -l io.cilium.server -l server1 $NETPERF_IMAGE
docker run -dt --net=$TEST_NET --name server2 -l io.cilium.server -l server2 $NETPERF_IMAGE
docker run -dt --net=$TEST_NET --name client -l io.cilium.client $NETPERF_IMAGE

# FIXME IPv6 DAD period
sleep 5

SERVER1_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server1)
NODE_ID=$(echo $SERVER1_IP | sed s/::/:/ | cut -d : -f 2,3 | sed s/://g)
NODE_ID=0x$NODE_ID
SERVER1_ID=$(cilium endpoint list | grep $SERVER1_IP | awk '{ print $1}')
SERVER2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server2)
SERVER2_ID=$(cilium endpoint list | grep $SERVER2_IP | awk '{ print $1}')

set -x

cat <<EOF | cilium -D policy import -
{
        "name": "io.cilium",
        "children": {
		"client": { },
		"server": {
			"rules": [{
				"allow": ["reserved:host", "../client"]
			}]
		}

	}
}
EOF

sudo cilium lb c /sys/fs/bpf/tc/globals/cilium_lb6_services 1
sudo cilium lb c /sys/fs/bpf/tc/globals/cilium_lb6_state 2

#LB_PORT=12865
#sudo cilium lb update-service 0 f00d::1:1 $LB_PORT 0 2 ::
#sudo cilium lb update-service 1 f00d::1:1 $LB_PORT 111 2 $SERVER1_IP
#sudo cilium lb update-service 2 f00d::1:1 $LB_PORT 111 2 $SERVER2_IP
#sudo cilium lb update-state 111 f00d::1:1 $LB_PORT

LB_PORT=0
sudo cilium lb update-service 0 f00d::1:1 $LB_PORT 0 2 ::
sudo cilium lb update-service 1 f00d::1:1 $LB_PORT 112 2 $SERVER1_IP
sudo cilium lb update-service 2 f00d::1:1 $LB_PORT 112 2 $SERVER2_IP
sudo cilium lb update-state 112 f00d::1:1 $LB_PORT

monitor_clear
docker exec -i client ping6 -c 4 f00d::1:1 || {
	abort "Error: Unable to reach netperf TCP IPv6 endpoint"
}

monitor_clear
docker exec -i client netperf -l 30 -t TCP_RR -H f00d::1:1 || {
	abort "Error: Unable to reach netperf TCP IPv6 endpoint"
}

cleanup
cilium -D policy delete io.cilium
