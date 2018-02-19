package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brotherpowers/ipsubnet"
)

// Tree object
type Tree struct {
	Devices map[string]*Device

	mu sync.Mutex
}

// BuildTree builds the config tree
func BuildTree(s *state) (*Tree, error) {
	t := &Tree{
		Devices: make(map[string]*Device),
	}

	var wg sync.WaitGroup

	for name, dev := range s.Devices {
		wg.Add(1)
		go func(name string, dev *device) {
			defer wg.Done()
			tDev, err := BuildDevice(s, dev)
			if err != nil {
				panic(err)
			}

			t.mu.Lock()
			t.Devices[name] = tDev
			t.mu.Unlock()
		}(name, dev)
	}

	wg.Wait()

	return t, nil
}

// BuildDevice
func BuildDevice(s *state, d *device) (*Device, error) {
	deviceLeaf := &Device{
		Vendor:     d.Vendor,
		Transport:  d.Transport,
		Persist:    d.Persist,
		Timeout:    d.Timeout,
		HostGroups: make(map[string][]string),
		Rules:      make(map[string][]*Rule),
	}

	for _, inc := range d.Includes {
		// get the policy
		policy, ok := s.Policies[inc]
		if !ok {
			return nil, fmt.Errorf("Unknown policy: %s", inc)
		}

		addObjectToHostGroup := func(g string) {
			if _, ok := deviceLeaf.HostGroups[g]; !ok {
				hosts := resolveHost(s, g)
				deviceLeaf.HostGroups[g] = hosts
			}
		}

		var rules []*Rule

		for _, rule := range policy.Rule {
			r := &Rule{}

			r.Protocol = expand(rule.Protocol)
			r.Action = rule.Policy
			r.Log = rule.Log
			r.Established = rule.Stateful
			r.Mirror = rule.Mirror

			src := rule.Source
			dst := rule.Destination

			if src.Object[0] == '@' {
				groupName := src.Object[1:]
				addObjectToHostGroup(groupName)
				r.SourcePrefix = groupName
			} else {
				if src.Object == "" {
					src.Object = "any"
				}

				if src.Object != "any" {
					parts := strings.SplitN(src.Object, "/", 2)

					subnetSize := 32
					if len(parts) == 2 {
						subnetSize, _ = strconv.Atoi(parts[1])
					}

					r.SourceIP = ipsubnet.SubnetCalculator(parts[0], subnetSize)
				}
			}

			if dst.Object[0] == '@' {
				groupName := dst.Object[1:]
				addObjectToHostGroup(groupName)
				r.DestinationPrefix = groupName
			} else {
				if dst.Object == "" {
					dst.Object = "any"
				}

				if dst.Object != "any" {
					parts := strings.SplitN(dst.Object, "/", 2)

					subnetSize := 32
					if len(parts) == 2 {
						subnetSize, _ = strconv.Atoi(parts[1])
					}

					r.DestinationIP = ipsubnet.SubnetCalculator(parts[0], subnetSize)
				}
			}

			if rule.Source.Port != "" && rule.Source.Port != "any" {
				r.SourcePorts = resolvePort(s, rule.Protocol, rule.Source.Port)
			}

			if rule.Destination.Port != "" && rule.Destination.Port != "any" {
				r.DestinationPorts = resolvePort(s, rule.Protocol, rule.Destination.Port)
			}

			rules = append(rules, r)
		}

		deviceLeaf.Rules[inc] = rules
	}

	return deviceLeaf, nil
}

// Device object
type Device struct {
	Vendor    string
	Transport string
	Persist   bool
	Timeout   time.Duration

	HostGroups map[string][]string
	Rules      map[string][]*Rule

	mu sync.Mutex
}

type Rule struct {
	Action                  string
	Established             bool
	Log                     bool
	Mirror                  bool
	Protocol                []string
	SourceIP                *ipsubnet.Ip
	SourcePrefix            string
	SourcePorts             []string
	DestinationIP           *ipsubnet.Ip
	DestinationPrefix       string
	DestinationPorts        []string
	DestinationIPSubnetSize string
	DestinationIPHostpart   string
}
