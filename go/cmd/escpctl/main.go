// Command escpctl is a small CLI for the tplink-easysmart/escp library.
//
//	go run ./cmd/escpctl -host 10.0.0.106 -user admin -pass admin1 dump
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"tplink-easysmart/escp"
)

func parseSpeed(s string) (escp.PortSpeed, error) {
	switch strings.ToLower(s) {
	case "auto":
		return escp.SpeedAuto, nil
	case "10h":
		return escp.Speed10MHalf, nil
	case "10f":
		return escp.Speed10MFull, nil
	case "100h":
		return escp.Speed100MHalf, nil
	case "100f":
		return escp.Speed100MFull, nil
	case "1000", "1000f":
		return escp.Speed1000MFull, nil
	}
	return 0, fmt.Errorf("unknown speed %q", s)
}

func onoff(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "on", "1", "true", "enable":
		return true, nil
	case "off", "0", "false", "disable":
		return false, nil
	}
	return false, fmt.Errorf("expected on|off, got %q", s)
}

func main() {
	host := flag.String("host", "", "switch IP address (required)")
	user := flag.String("user", "admin", "management username")
	pass := flag.String("pass", "admin1", "management password")
	timeout := flag.Duration("timeout", 3*time.Second, "per-request timeout")
	verbose := flag.Bool("v", false, "log every packet")
	flag.Parse()

	args := flag.Args()
	cmd := "info"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	if *host == "" {
		fmt.Fprintln(os.Stderr, "usage: escpctl -host IP [-user u] [-pass p] [-v] <command> [args]")
		os.Exit(2)
	}

	c := escp.NewClient(*host, *user, *pass)
	c.Timeout = *timeout
	c.Verbose = *verbose
	c.Logger = func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }
	defer c.Close()
	ctx := context.Background()

	if cmd == "discover" {
		info, err := c.Discover(ctx)
		if err != nil {
			fatal("discover", err)
		}
		fmt.Println(info)
		return
	}

	if err := c.Login(ctx); err != nil {
		fatal("login", err)
	}
	fmt.Printf("security : %s\n", c.Mode)

	switch cmd {
	case "info":
		fmt.Printf("system   : %s\n", c.SystemInfo())

	case "stats":
		stats, err := c.GetPortStats(ctx)
		if err != nil {
			fatal("stats", err)
		}
		fmt.Printf("%-5s %12s %10s %12s %10s\n", "port", "txGood", "txBad", "rxGood", "rxBad")
		for _, s := range stats {
			fmt.Printf("%-5d %12d %10d %12d %10d\n", s.Port, s.TxGood, s.TxBad, s.RxGood, s.RxBad)
		}

	case "ports":
		ports, err := c.GetPorts(ctx)
		if err != nil {
			fatal("ports", err)
		}
		for _, p := range ports {
			fmt.Printf("port %d enabled=%v raw=%x\n", p.Port, p.Enabled, p.Raw)
		}

	case "dump":
		dump(ctx, c)

	case "set-port":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: set-port <port> <on|off> [speed] [flow on|off]")
			os.Exit(2)
		}
		port, err := strconv.Atoi(args[0])
		if err != nil {
			fatal("set-port", err)
		}
		en, err := onoff(args[1])
		if err != nil {
			fatal("set-port", err)
		}
		cfg := escp.PortConfig{Port: port, Enabled: en, Speed: escp.SpeedAuto}
		if len(args) >= 3 {
			if cfg.Speed, err = parseSpeed(args[2]); err != nil {
				fatal("set-port", err)
			}
		}
		if len(args) >= 5 && strings.EqualFold(args[3], "flow") {
			if cfg.FlowControl, err = onoff(args[4]); err != nil {
				fatal("set-port", err)
			}
		}
		if err := c.SetPort(ctx, cfg); err != nil {
			fatal("set-port", err)
		}
		fmt.Printf("port %d set: enabled=%v speed=%s flow=%v\n", port, en, cfg.Speed, cfg.FlowControl)

	case "set-description":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: set-description <name>")
			os.Exit(2)
		}
		if err := c.SetDescription(ctx, args[0]); err != nil {
			fatal("set-description", err)
		}
		fmt.Println("description set")

	case "set-led":
		v, err := onoff(arg(args, 0, "on"))
		if err != nil {
			fatal("set-led", err)
		}
		if err := c.SetLED(ctx, v); err != nil {
			fatal("set-led", err)
		}
		fmt.Printf("LED %v\n", v)

	case "set-igmp":
		v, err := onoff(arg(args, 0, "on"))
		if err != nil {
			fatal("set-igmp", err)
		}
		if err := c.SetIGMP(ctx, v); err != nil {
			fatal("set-igmp", err)
		}
		fmt.Printf("IGMP snooping %v\n", v)

	case "set-loop":
		v, err := onoff(arg(args, 0, "on"))
		if err != nil {
			fatal("set-loop", err)
		}
		if err := c.SetLoopPrevention(ctx, v); err != nil {
			fatal("set-loop", err)
		}
		fmt.Printf("loop prevention %v\n", v)

	case "set-ip":
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: set-ip <dhcp|static> <ip> <mask> <gw> [mgmt-vlan]")
			os.Exit(2)
		}
		dhcp := strings.EqualFold(args[0], "dhcp")
		vlan := 1
		if len(args) >= 5 {
			vlan, _ = strconv.Atoi(args[4])
		}
		err := c.SetIP(ctx, dhcp, net.ParseIP(args[1]), net.ParseIP(args[2]), net.ParseIP(args[3]), uint16(vlan))
		if err != nil {
			fatal("set-ip", err)
		}
		fmt.Println("IP settings applied")

	case "set-qos":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: set-qos <0=port|1=802.1p|2=dscp>")
			os.Exit(2)
		}
		mode, err := strconv.Atoi(args[0])
		if err != nil {
			fatal("set-qos", err)
		}
		if err := c.SetQoSMode(ctx, mode); err != nil {
			fatal("set-qos", err)
		}
		fmt.Printf("QoS mode %d\n", mode)

	case "save":
		if err := c.SaveConfig(ctx); err != nil {
			fatal("save", err)
		}
		fmt.Println("configuration saved")

	case "reboot":
		if err := c.Reboot(ctx); err != nil {
			fatal("reboot", err)
		}
		fmt.Println("reboot requested")

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}

func dump(ctx context.Context, c *escp.Client) {
	fmt.Printf("system   : %s\n", c.SystemInfo())

	if enabled, suppression, err := c.GetIGMP(ctx); err == nil {
		fmt.Printf("igmp     : enabled=%v suppression=%v\n", enabled, suppression)
	} else {
		fmt.Printf("igmp     : error: %v\n", err)
	}
	if v, err := c.GetLoopPrevention(ctx); err == nil {
		fmt.Printf("loop     : %v\n", v)
	}
	if m, err := c.GetMirror(ctx); err == nil {
		fmt.Printf("mirror   : enabled=%v port=%d ingress=%v egress=%v\n", m.Enabled, m.MirrorPort, m.Ingress, m.Egress)
	}
	if trunks, err := c.GetTrunks(ctx); err == nil {
		fmt.Printf("lags     : %v\n", trunks)
	}
	if mode, err := c.GetQoSMode(ctx); err == nil {
		pri, _ := c.GetPortPriorities(ctx)
		fmt.Printf("qos      : mode=%d priorities=%v\n", mode, pri)
	}
	if in, eg, err := c.GetBandwidth(ctx); err == nil {
		fmt.Printf("bandwidth: ingress=%v egress=%v\n", in, eg)
	}
	if sc, err := c.GetStormControl(ctx); err == nil {
		fmt.Printf("storm    : %v\n", sc)
	}
	if enabled, vlans, pvids, err := c.GetDot1QVLANs(ctx); err == nil {
		fmt.Printf("802.1q   : enabled=%v pvids=%v\n", enabled, pvids)
		for _, v := range vlans {
			fmt.Printf("           vlan %d %q tagged=%v untagged=%v\n", v.VID, v.Name, v.Tagged, v.Untagged)
		}
	}
	if enabled, vlans, err := c.GetPortVLANs(ctx); err == nil {
		fmt.Printf("portvlan : enabled=%v %v\n", enabled, vlans)
	}
	if enabled, uplink, err := c.GetMTUVLAN(ctx); err == nil {
		fmt.Printf("mtu-vlan : enabled=%v uplink=%d\n", enabled, uplink)
	}

	if stats, err := c.GetPortStats(ctx); err == nil {
		fmt.Printf("%-5s %12s %12s\n", "port", "txGood", "rxGood")
		for _, s := range stats {
			fmt.Printf("%-5d %12d %12d\n", s.Port, s.TxGood, s.RxGood)
		}
	}
}

func arg(args []string, i int, def string) string {
	if i < len(args) {
		return args[i]
	}
	return def
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}
