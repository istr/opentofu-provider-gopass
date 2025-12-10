// Copyright (c) Ingo Struck
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"log"

	"git.ingo-struck.com/opentofu/terraform-provider-gopass/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// version is set via ldflags at build time
var version = "dev"

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.opentofu.org/istr/gopass",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
