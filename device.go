package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type device struct {
	Vendor    string
	Transport string
	Persist   bool
	Timeout   time.Duration
	Includes  []string

	HostGroups map[string][]string

	mu sync.Mutex
}

// NewDevice creates a new device
func newDevice(name string) *device {
	d := &device{}

	d.HostGroups = make(map[string][]string)
	d.Load(name)

	return d
}

func (d *device) Load(name string) {
	f, err := os.Open(fmt.Sprintf("%s/%s", dev, name))
	if err != nil {
		log.Fatalf("main: Failed to read file %s/%s", dev, name)
	}

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line[0] == '#' {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		switch parts[0] {
		case "vendor":
			d.Vendor = parts[1]
		case "transport":
			d.Transport = parts[1]
		case "save_config":
			persist, err := strconv.ParseBool(parts[1])
			if err != nil {
				log.Fatalf("device: invalid value for save_config `%s`", parts[1])
			}
			d.Persist = persist
		case "timeout":
			duration, err := time.ParseDuration(fmt.Sprintf("%ss", parts[1]))
			if err != nil {
				log.Fatalf("device: invalid value for timeout `%s`", parts[1])
			}
			d.Timeout = duration
		case "include":
			d.addInclude(parts[1])
		default:
			log.Warnf("device: unknown key %s", parts[0])
		}
	}
}

func (d *device) Resolve(s *state) error {
	for _, i := range d.Includes {
		p, ok := s.Policies[i]
		if !ok {
			return fmt.Errorf("Unknown policy: %s", i)
		}

		log.Debugf("Including policy: %s", i)

		for _, r := range p.Rule {
			if o := r.Destination.Object; o[0] == '@' {
				// check if it exists
				if _, ok := d.HostGroups[o[1:]]; !ok {
					hosts := resolveHost(s, o[1:])
					log.Debugf("resolved %s to: %v", o[1:], hosts)

					d.HostGroups[o[1:]] = hosts
				}
			}

		}
	}

	return nil
}

func (d *device) addInclude(include string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.Includes = append(d.Includes, include)
}

func resolveHost(s *state, host string) []string {
	var result []string
	obj, ok := s.Hosts[host]
	if !ok {
		log.Warnf("Failed to find host object: %s", host)
		return []string{}
	}
	for _, entry := range obj.Entries {
		if entry[0] == '@' {
			result = append(result, resolveHost(s, entry[1:])...)
		} else {
			result = append(result, entry)
		}
	}

	return result
}

func lookupPort(proto, port string) string {
	var results []string

	var pair []string

	switch strings.IndexAny(port, "-") {
	case -1:
		pair = []string{port}
	case 0:
		pair = []string{"1", port[1:]}
	case len(port) - 1:
		pair = []string{port[0 : len(port)-1], "65535"}
	default:
		pair = strings.SplitN(port, "-", 2)
	}

	for _, p := range pair {
		pint, err := net.LookupPort(proto, p)
		if err != nil {
			panic(err)
		}
		results = append(results, strconv.Itoa(pint))
	}

	return strings.Join(results, "-")
}

func resolvePort(s *state, proto, port string) []string {
	var result []string

	if port[0] != '@' {
		return []string{lookupPort(proto, port)}
	}

	obj, ok := s.Ports[port[1:]]
	if !ok {
		log.Warnf("Failed to find port object: %s", port)
		return []string{}
	}

	for _, entry := range obj.Entries {
		if entry[0] == '@' {
			result = append(result, resolvePort(s, proto, entry)...)
		} else {
			result = append(result, lookupPort(proto, entry))
		}
	}

	return result
}
