/*
 * Go module for domain whois
 * http://www.likexian.com/
 *
 * Copyright 2014, Kexian Li
 * Released under the Apache License, Version 2.0
 *
 */

package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

const (
	WHOIS_DOMAIN = "whois-servers.net"
	WHOIS_PORT   = "43"
)

func Version() string {
	return "0.1.0"
}

func Author() string {
	return "[Li Kexian](http://www.likexian.com/)"
}

func License() string {
	return "Apache License, Version 2.0"
}

func Whois(domain string, servers ...string) (result string, err error) {
	result, err = query(domain, servers...)
	if err != nil {
		return
	}

	start := strings.Index(result, "Whois Server:")
	if start == -1 {
		return
	}

	start += 13
	end := strings.Index(result[start:], "\n")
	server := strings.Trim(strings.Replace(result[start:start+end], "\r", "", -1), " ")
	tmp_result, err := query(domain, server)
	if err != nil {
		return
	}

	result += tmp_result

	return
}

func query(domain string, servers ...string) (result string, err error) {
	var server string
	if len(servers) == 0 || servers[0] == "" {
		whoisServer, err := Server(domain)
		if err != nil || whoisServer == "" {
			domains := strings.SplitN(domain, ".", 2)
			if len(domains) != 2 {
				err = fmt.Errorf("Domain %s is invalid.", domain)

				return result, err
			}
			server = domains[1] + "." + WHOIS_DOMAIN
		} else {
			server = whoisServer
		}
	} else {
		server = servers[0]
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, WHOIS_PORT), time.Second*30)
	if err != nil {
		return
	}

	conn.Write([]byte(domain + "\r\n"))
	var buffer []byte
	buffer, err = ioutil.ReadAll(conn)
	if err != nil {
		return
	}

	conn.Close()
	result = string(buffer[:])

	return
}
