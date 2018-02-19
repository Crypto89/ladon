package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"text/template"

	log "github.com/sirupsen/logrus"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var dev = "/Users/jwijnands/ebay/ecg-networking/ninjadevices"
var deviceDir = "/Users/jwijnands/ebay/ecg-networking/ninjadevices"
var ruleDir = "/Users/jwijnands/ebay/ecg-networking/policy"
var objectDir = "/Users/jwijnands/ebay/ecg-networking/objects"

var mu sync.Mutex

var (
	app   = kingpin.New("ladon", "Fast ACLCL parser")
	debug = app.Flag("debug", "Enable debug mode").Bool()
	lint  = app.Command("lint", "Check the configuration for syntax errors")

	render  = app.Command("render", "Render device configuration")
	devices = render.Arg("device", "Render a single device").Default("all").Strings()

	dot = app.Command("dot", "Generate dot file")
)

type config struct {
	Devices string
}

func init() {
	// log.SetLevel(log.DebugLevel)
}

func add(x, y int) int {
	return (x + y)
}

func expand(proto string) []string {
	if proto == "tcpudp" {
		return []string{"tcp", "udp"}
	}
	return []string{proto}
}

func explode(port string) []string {
	return strings.SplitN(port, "-", 2)
}

func renderDevice(typ, name string, s *Device) {
	funcs := template.FuncMap{
		"add":     add,
		"trim":    strings.Trim,
		"lookup":  lookupPort,
		"expand":  expand,
		"explode": explode,
	}

	t := template.Must(template.New(fmt.Sprintf("%s.tmpl", typ)).Funcs(funcs).ParseFiles(
		"/Users/jwijnands/go/src/github.com/Crypto89/ladon/templates/junos.tmpl",
		"/Users/jwijnands/go/src/github.com/Crypto89/ladon/templates/ios.tmpl",
		"/Users/jwijnands/go/src/github.com/Crypto89/ladon/templates/graph.tmpl",
	))

	var buffer bytes.Buffer
	log.Debugf("rending device: %s", name)
	if err := t.Execute(&buffer, s); err != nil {
		log.Warnf("error rendering: %s", err)
	}

	ioutil.WriteFile(fmt.Sprintf("./renders/%s.out", name), buffer.Bytes(), 0644)
}

func buildState() *state {
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("failed to read rules: %s", r)
		}
	}()

	s := newState()
	s.loadPolicies(ruleDir)
	s.loadObject(objectDir)
	s.loadDevices(deviceDir)

	return s
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

func cmdLint() {
	defer timeTrack(time.Now(), "lint")

	s := buildState()

	log.Infof("Loaded %d hosts", len(s.Hosts))
	log.Infof("Loaded %d ports", len(s.Ports))
	log.Infof("Loaded %d policies", len(s.Policies))
	log.Infof("Loaded %d devices", len(s.Devices))
	log.Info("cache compiled correctly")

	tree, err := BuildTree(s)
	if err != nil {
		log.Fatalf("Failed to resolve dependency tree: %s", err)
	}

	referencedHosts := make(map[string]int)
	// referencedPorts := make(map[string]int)

	for _, device := range tree.Devices {
		for hgName := range device.HostGroups {
			if _, ok := referencedHosts[hgName]; ok {
				referencedHosts[hgName]++
			} else {
				referencedHosts[hgName] = 0
			}
		}
	}

	for host := range s.Hosts {
		if cnt, ok := referencedHosts[host]; ok {
			log.Debugf("host %s has %d references", host, cnt)
		} else {
			log.Warnf("host %-50s has 0 references!", host)
		}
	}
}

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case lint.FullCommand():
		cmdLint()
		return
	case dot.FullCommand():
		s := buildState()
		tree, err := BuildTree(s)
		if err != nil {
			log.Fatalf("main: err builing tree %s", err)
		}

		renderDevice("graph", "cfw1.ams5", tree.Devices["cfw1.ams5"])
	case render.FullCommand():
		defer timeTrack(time.Now(), "render")
		s := buildState()

		tree, err := BuildTree(s)
		if err != nil {
			log.Fatalf("main: err building tree: %s", err)
		}

		var w sync.WaitGroup
		var renderDevices []string

		if (*devices)[0] != "all" {
			renderDevices = *devices
		} else {
			for name := range tree.Devices {
				renderDevices = append(renderDevices, name)
			}
		}

		for _, name := range renderDevices {
			d, ok := tree.Devices[name]
			if !ok {
				log.Fatalf("Unknown device: %s", name)
			}

			w.Add(1)
			go func(name string) {
				defer w.Done()
				renderDevice(d.Vendor, name, d)
			}(name)
		}

		w.Wait()
	}

}
