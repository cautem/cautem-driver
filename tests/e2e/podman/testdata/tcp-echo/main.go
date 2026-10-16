// SPDX-FileCopyrightText: Copyright (c) 2026 the cautem authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "spawn-orphans" {
		spawnOrphans(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "spawn-child" {
		spawnChild(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "--spawn-child-marker" {
		writeChildTermination(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: tcp-echo <serve-tcp|serve-udp|probe-tcp|probe-udp|probe-connect> <address> | tcp-echo spawn-orphans <count> <seconds> | tcp-echo spawn-child <pid-file> <exit-file> <seconds>")
		os.Exit(3)
	}

	var code int
	switch os.Args[1] {
	case "serve-tcp":
		code = serveTCP(os.Args[2])
	case "serve-udp":
		code = serveUDP(os.Args[2])
	case "probe-tcp":
		code = probeTCP(os.Args[2])
	case "probe-udp":
		code = probeUDP(os.Args[2])
	case "probe-connect":
		code = probeConnect(os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "unknown tcp-echo command", os.Args[1])
		code = 3
	}
	os.Exit(code)
}

func spawnChild(pidFile, exitFile, seconds string) {
	duration, err := strconv.Atoi(seconds)
	if err != nil || duration < 1 || duration > 600 {
		fmt.Fprintf(os.Stderr, "invalid child duration %q\n", seconds)
		os.Exit(3)
	}
	child := exec.Command(os.Args[0], "--spawn-child-marker", pidFile, exitFile)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start timeout child: %v\n", err)
		os.Exit(3)
	}

	// Keep the ExecSandbox process alive until its execution timeout kills the
	// process group. The child records that it received termination so the
	// Gateway integration test can verify descendant cleanup.
	time.Sleep(time.Duration(duration) * time.Second)
	if err := child.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "wait for timeout child: %v\n", err)
		os.Exit(3)
	}
}

func writeChildTermination(pidFile, exitFile string) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write timeout child PID: %v\n", err)
		os.Exit(3)
	}
	<-signals
	signal.Stop(signals)
	if err := os.WriteFile(exitFile, []byte(strconv.Itoa(os.Getpid())+" terminated\n"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write timeout child termination: %v\n", err)
		os.Exit(3)
	}
	os.Exit(0)
}

func spawnOrphans(countArg, seconds string) {
	count, err := strconv.Atoi(countArg)
	if err != nil || count < 1 || count > 256 {
		fmt.Fprintf(os.Stderr, "invalid orphan count %q\n", countArg)
		os.Exit(3)
	}
	duration, err := strconv.Atoi(seconds)
	if err != nil || duration < 1 || duration > 600 {
		fmt.Fprintf(os.Stderr, "invalid orphan duration %q\n", seconds)
		os.Exit(3)
	}
	pids := make([]string, 0, count)
	for range count {
		child := exec.Command("sleep", seconds)
		child.Stdin = strings.NewReader("")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "start orphan probe: %v\n", err)
			os.Exit(3)
		}
		pids = append(pids, strconv.Itoa(child.Process.Pid))
	}
	if err := os.WriteFile("/tmp/cautem-process-event-child-pids", []byte(strings.Join(pids, "\n")), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write orphan probe PIDs: %v\n", err)
		os.Exit(3)
	}
	fmt.Fprintf(os.Stdout, "spawned %d adopted-child probes: %s\n", len(pids), strings.Join(pids, ","))
	os.Exit(0)
}

func serveTCP(address string) int {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen TCP:", err)
		return 3
	}
	fmt.Println("READY tcp")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept TCP:", err)
			return 3
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func serveUDP(address string) int {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen UDP:", err)
		return 3
	}
	fmt.Println("READY udp")
	buffer := make([]byte, 2048)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read UDP:", err)
			return 3
		}
		if _, err := conn.WriteTo(buffer[:n], peer); err != nil {
			fmt.Fprintln(os.Stderr, "write UDP:", err)
			return 3
		}
	}
}

func probeTCP(address string) int {
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		fmt.Println("BLOCKED")
		return 0
	}
	_ = conn.Close()
	fmt.Fprintln(os.Stderr, "TCP probe connected to", address)
	return 2
}

func probeUDP(address string) int {
	conn, err := net.DialTimeout("udp", address, time.Second)
	if err != nil {
		fmt.Println("BLOCKED")
		return 0
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("podman-policy-probe")); err != nil {
		fmt.Println("BLOCKED")
		return 0
	}
	var response [1]byte
	if _, err := conn.Read(response[:]); err != nil {
		fmt.Println("BLOCKED")
		return 0
	}
	fmt.Fprintln(os.Stderr, "UDP probe received a response from", address)
	return 2
}

func probeConnect(target string) int {
	proxyAddr := strings.TrimSpace(os.Getenv("HTTPS_PROXY"))
	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: target}})
	if err != nil || proxyAddr == "" || proxyURL == nil {
		fmt.Fprintln(os.Stderr, "HTTPS_PROXY is not configured for policy probe")
		return 3
	}
	conn, err := net.DialTimeout("tcp", proxyURL.Host, time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot reach configured HTTP proxy", err)
		return 3
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		fmt.Fprintln(os.Stderr, "write CONNECT request:", err)
		return 3
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		fmt.Fprintln(os.Stderr, "read CONNECT response:", err)
		return 3
	}
	if response.StatusCode != http.StatusForbidden {
		fmt.Fprintln(os.Stderr, "proxy CONNECT status", response.StatusCode, "for", target, "; want 403")
		return 2
	}
	fmt.Println("PROXY", response.Status)
	return 0
}
