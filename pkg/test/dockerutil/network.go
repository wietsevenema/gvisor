// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dockerutil

import (
	"context"
	"fmt"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// Network is a docker network.
type Network struct {
	ctx        context.Context
	client     *client.Client
	id         string
	logger     testutil.Logger
	Name       string
	containers []*Container
	Subnet     *net.IPNet
}

// NewNetwork sets up the struct for a Docker network. Names of networks
// will be unique.
func NewNetwork(logger testutil.Logger) *Network {
	client, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		logger.Logf("create client failed with: %v", err)
		return nil
	}

	ctx := context.Background()
	client.NegotiateAPIVersion(ctx)

	return &Network{
		ctx:    ctx,
		logger: logger,
		Name:   testutil.RandomID(logger.Name()),
		client: client,
	}
}

func (n *Network) networkCreate() types.NetworkCreate {

	var subnet string
	if n.Subnet != nil {
		subnet = n.Subnet.String()
	}

	config := network.IPAMConfig{
		Subnet: subnet,
	}
	ipam := network.IPAM{
		Config: []network.IPAMConfig{config},
	}

	return types.NetworkCreate{
		CheckDuplicate: true,
		IPAM:           &ipam,
	}
}

// Create is analogous to 'docker network create'.
func (n *Network) Create() error {

	opts := n.networkCreate()
	resp, err := n.client.NetworkCreate(n.ctx, n.Name, opts)
	if err != nil {
		return fmt.Errorf("network create: %v", err)
	}
	n.id = resp.ID
	return nil
}

// Connect is analogous to 'docker network connect' with the arguments provided.
func (n *Network) Connect(container *Container, ipv4, ipv6 string) error {
	settings := network.EndpointSettings{
		IPAMConfig: &network.EndpointIPAMConfig{
			IPv4Address: ipv4,
			IPv6Address: ipv6,
		},
	}
	err := n.client.NetworkConnect(n.ctx, n.id, container.id, &settings)
	if err == nil {
		n.containers = append(n.containers, container)
	}
	return err
}

// Inspect returns this network's info.
func (n *Network) Inspect() (types.NetworkResource, error) {
	return n.client.NetworkInspect(n.ctx, n.id, types.NetworkInspectOptions{Verbose: true})
}

// Cleanup cleans up the docker network and all the containers attached to it.
func (n *Network) Cleanup() error {
	for _, c := range n.containers {
		c.CleanUp()
	}
	n.containers = nil

	return n.client.NetworkRemove(n.ctx, n.id)
}
