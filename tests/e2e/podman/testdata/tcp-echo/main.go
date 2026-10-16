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
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: tcp-echo <serve-tcp|serve-udp|probe-tcp|probe-udp|probe-connect> <address>")
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
