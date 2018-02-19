package main

import (
	"io/ioutil"
	"strings"
	"sync"

	"github.com/Crypto89/ladon/parser"
	log "github.com/sirupsen/logrus"
)

type state struct {
	mu       sync.Mutex
	Policies map[string]*parser.RuleSet
	Ports    map[string]*parser.Ports
	Hosts    map[string]*parser.Hosts
	Devices  map[string]*device
}

func newState() *state {
	return &state{
		Policies: make(map[string]*parser.RuleSet),
		Ports:    make(map[string]*parser.Ports),
		Hosts:    make(map[string]*parser.Hosts),
		Devices:  make(map[string]*device),
	}
}

func (s *state) addPolicy(name string, rs *parser.RuleSet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Policies[name] = rs
}

func (s *state) addHost(name string, o *parser.Hosts) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Hosts[name] = o
}

func (s *state) addPort(name string, o *parser.Ports) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Ports[name] = o
}

func (s *state) addDevice(name string, o *device) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Devices[name] = o
}

func (s *state) loadObject(dir string) {
	log.Debug("Building object cache")
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("main: can't read policies: %s", err)
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".swp") {
			continue
		}

		i := strings.LastIndex(f.Name(), ".")
		obj, typ := f.Name()[:i], f.Name()[i+1:]

		switch typ {
		case "hosts":
			s.addHost(obj, loadHosts(f.Name()))
		case "ports":
			s.addPort(obj, loadPorts(f.Name()))
		default:
		}
	}
}

func (s *state) loadPolicies(dir string) {
	log.Debug("Building policy cache")
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("main: can't read policies: %s", err)
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".swp") {
			continue
		}

		s.addPolicy(f.Name(), loadRuleSet(f.Name()))
	}
}

func (s *state) loadDevices(dir string) {
	log.Debug("Building devices cache")
	devicesFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("can't read dir: %s", err)
	}

	for _, deviceFile := range devicesFiles {
		if strings.HasSuffix(deviceFile.Name(), ".ignore") {
			log.Infof("main: ignoring %s", deviceFile.Name())
			continue
		}

		s.addDevice(deviceFile.Name(), newDevice(deviceFile.Name()))
	}
}
