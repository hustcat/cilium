//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package lb

/*
#cgo CFLAGS: -I../include
#include <linux/bpf.h>
#include <sys/resource.h>
*/
import "C"

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/bpf"
	"github.com/cilium/cilium/common/types"
	"github.com/op/go-logging"

	"github.com/codegangsta/cli"
)

var (
	log     = logging.MustGetLogger("cilium-net")
	mapFile string
)

const (
	mapSize            = 1024
	errInvalidArgument = -1
	errIOFailure       = -2
)

// lbServices : LBKey => LBService, file cilium_lb6_services
// lbState    : state => LBService, file cilium_lb_state
const (
	lbServices = 1
	lbState    = 2
)

type LBKey struct {
	address v6Addr
	dport   uint16
	slave   uint16
}

type LBService struct {
	address v6Addr
	port    uint16
	count   uint16
}

type LBState struct {
	address v6Addr
	port    uint16
}

type LBMap struct {
	fd int
}

type v6Addr types.IPv6

func printErrorAndExit(ctx *cli.Context, err string, code int) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	fmt.Fprintf(os.Stderr, "Usage: %s %s %s\n", ctx.App.Name, ctx.Command.Name,
		ctx.Command.ArgsUsage)
	os.Exit(code)
	return
}

func printArgsUsageAndExit(ctx *cli.Context) {
	printErrorAndExit(ctx, "Incorrect number of arguments.", errInvalidArgument)
	return
}

var (
	// CliCommand is the command that will be used in cilium-net main program.
	CliCommand cli.Command
)

func init() {
	CliCommand = cli.Command{
		Name:  "lb",
		Usage: "configure load balancer",
		Subcommands: []cli.Command{
			{
				Name:      "init",
				Aliases:   []string{"i"},
				Usage:     "initialize load balancer",
				ArgsUsage: "<lb-ip> <server-prefix>",
				Action:    lbInitialize,
			},
			{
				Name:      "create",
				Aliases:   []string{"c"},
				Usage:     "creates map on the given <map file>",
				ArgsUsage: "<map file> <lbtype>",
				Action:    lbCreateMap,
			},
			{
				Name:   "dump-service",
				Usage:  "dumps map present on the given <map file>",
				Action: lbDumpServices,
				Flags: []cli.Flag{
					cli.StringFlag{
						Destination: &mapFile,
						Name:        "file, f",
						Value:       "/sys/fs/bpf/tc/globals/cilium_lb6_services",
					},
				},
			},
			{
				Name:   "dump-state",
				Usage:  "dumps map present on the given <map file>",
				Action: lbDumpState,
				Flags: []cli.Flag{
					cli.StringFlag{
						Destination: &mapFile,
						Name:        "file, f",
						Value:       "/sys/fs/bpf/tc/globals/cilium_lb6_state",
					},
				},
			},
			{
				Name:      "get",
				Aliases:   []string{"g"},
				Usage:     "gets key's value of the given <map file>",
				ArgsUsage: "<map file> <maptype 1> <ipv6 addr> <dport> | <map file> <maptype 2> <state>",
				Action:    lbLookupKey,
			},
			{
				Name:      "update-service",
				Aliases:   []string{"u"},
				Usage:     "updates key's value of the given <map file>",
				ArgsUsage: "<ipv6 addr> <port> <state> <count> <lxc-id> <node-id>",
				Action:    lbUpdateService,
				Flags: []cli.Flag{
					cli.StringFlag{
						Destination: &mapFile,
						Name:        "file, f",
						Value:       "/sys/fs/bpf/tc/globals/cilium_lb6_services",
					},
				},
			},
			{
				Name:      "update-state",
				Aliases:   []string{"u"},
				Usage:     "update LB state",
				ArgsUsage: "<state> <ipv6 addr> <port>",
				Action:    lbUpdateState,
				Flags: []cli.Flag{
					cli.StringFlag{
						Destination: &mapFile,
						Name:        "file, f",
						Value:       "/sys/fs/bpf/tc/globals/cilium_lb6_state",
					},
				},
			},
			{
				Name:    "delete",
				Aliases: []string{"D"},
				Action:  lbDeleteKey,
			},
		},
	}
}

func lbInitialize(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		printArgsUsageAndExit(ctx)
		return
	}

	globalsDir := filepath.Join(common.CiliumPath, "globals")
	if err := os.MkdirAll(globalsDir, 0755); err != nil {
		log.Fatalf("Could not create runtime directory %s: %s", globalsDir, err)
	}

	if err := os.Chdir(common.CiliumPath); err != nil {
		log.Fatalf("Could not change to runtime directory %s: \"%s\"",
			common.CiliumPath, err)
	}

	f, err := os.Create("./globals/lb_config.h")
	if err != nil {
		log.Fatalf("Could not create lb_config.h: %s\n", err)
	}

	fw := bufio.NewWriter(f)

	ip := ctx.Args().First()
	if ip6 := net.ParseIP(ip); ip6 != nil && ip6.To16() != nil {
		fw.WriteString(common.FmtDefineArray("ROUTER_IP", ip6.To16()))
	} else {
		log.Fatalf("Invalid ipv6 address %s\n", ip)
	}

	sprefix := ctx.Args().Get(1)
	if ip6 := net.ParseIP(sprefix); ip6 != nil && ip6.To16() != nil {
		fw.WriteString(common.FmtDefineArray("SERVER_PREFIX", ip6.To16()))
	} else {
		log.Fatalf("Invalid ipv6 address %s\n", sprefix)
	}

	fw.Flush()
	f.Close()
}

func lbOpenMap(path string, lbtype uint) (*LBMap, error) {
	var fd int

	rl := syscall.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	err := syscall.Setrlimit(C.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return nil, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

	if _, err = os.Stat(path); os.IsNotExist(err) {
		mapDir := filepath.Dir(path)
		if _, err = os.Stat(mapDir); os.IsNotExist(err) {
			if err = os.MkdirAll(mapDir, 0755); err != nil {
				return nil, fmt.Errorf("Unable create map base directory: %s", err)
			}
		}

		if lbtype == lbServices {
			fd, err = bpf.CreateMap(
				C.BPF_MAP_TYPE_HASH,
				uint32(unsafe.Sizeof(LBKey{})),
				uint32(unsafe.Sizeof(LBService{})),
				mapSize,
			)
		} else if lbtype == lbState {
			fd, err = bpf.CreateMap(
				C.BPF_MAP_TYPE_HASH,
				uint32(unsafe.Sizeof(uint16(0))),
				uint32(unsafe.Sizeof(LBState{})),
				mapSize,
			)
		} else {
			return nil, fmt.Errorf("Incorrect lbtype %d.\n", lbtype)
		}

		if err != nil {
			return nil, err
		}

		err = bpf.ObjPin(fd, path)
		if err != nil {
			return nil, err
		}
	} else {
		fd, err = bpf.ObjGet(path)
		if err != nil {
			return nil, err
		}
	}

	m := new(LBMap)
	m.fd = fd

	return m, nil
}

func lbCreateMap(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		printArgsUsageAndExit(ctx)
		return
	}
	file := ctx.Args().First()

	lbtype, err := strconv.ParseUint(ctx.Args().Get(1), 0, 8)
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}
	_, err = lbOpenMap(file, uint(lbtype))
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}
}

func lbDumpServices(ctx *cli.Context) {
	var key, nextKey LBKey

	fd, err := bpf.ObjGet(mapFile)
	if err != nil {
		printErrorAndExit(ctx, "Failed to open file", errInvalidArgument)
		return
	}

	for {
		var lbval LBService
		err := bpf.GetNextKey(
			fd,
			unsafe.Pointer(&key),
			unsafe.Pointer(&nextKey),
		)

		if err != nil {
			break
		}

		err = bpf.LookupElement(
			fd,
			unsafe.Pointer(&nextKey),
			unsafe.Pointer(&lbval),
		)

		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(errIOFailure)
			return
		}
		fmt.Printf("key:%#x, count:%d address:%#x port:%d\n",
			nextKey, lbval.count, lbval.address, common.Swab16(lbval.port))

		key = nextKey
	}
}

func lbDumpState(ctx *cli.Context) {
	var key, nextKey uint16

	fd, err := bpf.ObjGet(mapFile)
	if err != nil {
		printErrorAndExit(ctx, "Failed to open file", errInvalidArgument)
		return
	}

	for {
		var lbval LBState
		err := bpf.GetNextKey(
			fd,
			unsafe.Pointer(&key),
			unsafe.Pointer(&nextKey),
		)

		if err != nil {
			break
		}

		err = bpf.LookupElement(
			fd,
			unsafe.Pointer(&nextKey),
			unsafe.Pointer(&lbval),
		)

		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(errIOFailure)
			return
		}
		fmt.Printf("key:%d, address:%#x, port:%#x\n",
			common.Swab16(nextKey), lbval.address, common.Swab16(lbval.port))

		key = nextKey
	}
}

func lookupLb1(file string, key *LBKey) (*LBService, error) {
	lbval := new(LBService)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		return nil, err
	}

	err = bpf.LookupElement(fd, unsafe.Pointer(key), unsafe.Pointer(lbval))

	return lbval, err
}

func lookupLb2(file string, key uint16) (*LBState, error) {
	lbval := new(LBState)

	fd, err := bpf.ObjGet(file)
	if err != nil {
		return nil, err
	}

	u16key := key
	err = bpf.LookupElement(fd, unsafe.Pointer(&u16key), unsafe.Pointer(lbval))

	return lbval, err
}

func lbLookupKey(ctx *cli.Context) {
	if len(ctx.Args()) < 2 {
		printArgsUsageAndExit(ctx)
		return
	}

	file := ctx.Args().Get(0)

	lbtype, err := strconv.ParseUint(ctx.Args().Get(1), 0, 8)
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}

	if lbtype == lbServices {
		key := LBKey{}
		iv6 := net.ParseIP(ctx.Args().Get(2))
		if len(iv6) != net.IPv6len {
			printErrorAndExit(ctx, "invalid IPv6", errInvalidArgument)
			return
		}
		copy(key.address[:], iv6)

		tmp, err := strconv.ParseUint(ctx.Args().Get(3), 0, 16)
		key.dport = common.Swab16(uint16(tmp))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			printArgsUsageAndExit(ctx)
			return
		}

		lbval, err := lookupLb1(file, &key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			printArgsUsageAndExit(ctx)
			return
		}

		fmt.Printf("key.address %v, key.dport %d\n",
			key.address, common.Swab16(key.dport))
		fmt.Printf("%+v\n", lbval)
	} else if lbtype == lbState {
		key, err := strconv.ParseUint(ctx.Args().Get(2), 0, 16)
		if err != nil {
			printArgsUsageAndExit(ctx)
			return
		}

		lbval, err := lookupLb2(file, common.Swab16(uint16(key)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(errIOFailure)
			return
		}

		fmt.Printf("key.dport %d\n", uint16(key))
		fmt.Printf("%+v\n", lbval)
	} else {
		fmt.Fprintf(os.Stderr, "Incorrect lbtype %d.\n", lbtype)
		printArgsUsageAndExit(ctx)
		return
	}
}

func lbUpdateService(ctx *cli.Context) {
	lbval := LBService{}
	key := LBKey{}

	if len(ctx.Args()) < 6 {
		printArgsUsageAndExit(ctx)
		return
	}

	tmp, err := strconv.ParseUint(ctx.Args().Get(0), 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	key.slave = uint16(tmp)

	iv6 := net.ParseIP(ctx.Args().Get(1))
	if len(iv6) != net.IPv6len {
		fmt.Fprintf(os.Stderr, "invalid IPv6\n")
		printErrorAndExit(ctx, "invalid IPv6\n", errInvalidArgument)
		return
	}
	copy(key.address[:], iv6)

	tmp, err = strconv.ParseUint(ctx.Args().Get(2), 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	lbval.port = common.Swab16(uint16(tmp))
	key.dport = lbval.port

	tmp, err = strconv.ParseUint(ctx.Args().Get(3), 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	state := uint16(tmp)

	count, err := strconv.ParseUint(ctx.Args().Get(4), 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	lbval.count = uint16(count)

	target, err := addressing.NewCiliumIPv6(ctx.Args().Get(5))
	target.SetState(state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv6 address: %s\n", err)
		return
	}
	copy(lbval.address[:], target)

	fd, err := bpf.ObjGet(mapFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}

	err = bpf.UpdateElement(fd, unsafe.Pointer(&key), unsafe.Pointer(&lbval), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
}

func lbUpdateState(ctx *cli.Context) {
	lbval := LBState{}

	if len(ctx.Args()) < 3 {
		printArgsUsageAndExit(ctx)
		return
	}

	tmp, err := strconv.ParseUint(ctx.Args().Get(0), 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	u16key := common.Swab16(uint16(tmp))

	iv6 := net.ParseIP(ctx.Args().Get(1))
	if len(iv6) != net.IPv6len {
		fmt.Fprintf(os.Stderr, "invalid IPv6\n")
		printErrorAndExit(ctx, "invalid IPv6\n", errInvalidArgument)
		return
	}
	copy(lbval.address[:], iv6)

	tmp, err = strconv.ParseUint(ctx.Args().Get(2), 0, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
	lbval.port = common.Swab16(uint16(tmp))

	fd, err := bpf.ObjGet(mapFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}

	err = bpf.UpdateElement(fd, unsafe.Pointer(&u16key), unsafe.Pointer(&lbval), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		printArgsUsageAndExit(ctx)
		return
	}
}

func lbDeleteKey(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		printArgsUsageAndExit(ctx)
		return
	}

	file := ctx.Args().Get(0)

	lbtype, err := strconv.ParseUint(ctx.Args().Get(1), 10, 8)
	if err != nil {
		printArgsUsageAndExit(ctx)
		return
	}

	obj, err := bpf.ObjGet(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		printArgsUsageAndExit(ctx)
		return
	}

	if lbtype == lbServices {
		key := LBKey{}
		iv6 := net.ParseIP(ctx.Args().Get(2))
		if len(iv6) != net.IPv6len {
			printErrorAndExit(ctx, "invalid IPv6\n", errInvalidArgument)
			return
		}
		copy(key.address[:], iv6)

		tmp, err := strconv.ParseUint(ctx.Args().Get(3), 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsageAndExit(ctx)
			return
		}
		key.dport = common.Swab16(uint16(tmp))

		err = bpf.DeleteElement(obj, unsafe.Pointer(&key))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsageAndExit(ctx)
			return
		}
	} else if lbtype == lbState {
		key, err := strconv.ParseUint(ctx.Args().Get(2), 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsageAndExit(ctx)
			return
		}

		u16key := common.Swab16(uint16(key))
		err = bpf.DeleteElement(obj, unsafe.Pointer(&u16key))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			printArgsUsageAndExit(ctx)
			return
		}
	}
}
