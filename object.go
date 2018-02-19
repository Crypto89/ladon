package main

import (
	"fmt"
	"os"

	"github.com/Crypto89/ladon/parser"
	log "github.com/sirupsen/logrus"
)

func loadHosts(name string) *parser.Hosts {
	f, err := os.Open(fmt.Sprintf("%s/%s", objectDir, name))
	if err != nil {
		log.Fatalf("ruleset: Failed to read file %s/%s", ruleDir, name)
	}

	obj, err := parser.ParseHosts(f)
	if err != nil {
		panic(err)
	}

	return obj
}

func loadPorts(name string) *parser.Ports {
	f, err := os.Open(fmt.Sprintf("%s/%s", objectDir, name))
	if err != nil {
		log.Fatalf("ruleset: Failed to read file %s/%s", ruleDir, name)
	}

	obj, err := parser.ParsePorts(f)
	if err != nil {
		panic(err)
	}

	return obj
}
