// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Balázs Toldi

package pfcpiface

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// A channel to bessd that is idle -- not yet connected, or put in idle mode by grpc-go after 30
// minutes without an RPC -- is not the datapath being down: IsConnected connects it.
func TestAnIdleChannelToBessIsConnected(t *testing.T) {
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer()
	go func() {
		if serr := srv.Serve(lis); serr != nil && !errors.Is(serr, grpc.ErrServerStopped) {
			t.Errorf("serve: %v", serr)
		}
	}()

	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), bessDialOptions()...)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	if s := conn.GetState(); s != connectivity.Idle {
		t.Fatalf("a new channel is %v, want IDLE", s)
	}

	b := &bess{conn: conn}
	if !b.IsConnected(nil) {
		t.Fatalf("an idle channel to a live bessd is reported down (state %v)", conn.GetState())
	}

	if s := conn.GetState(); s != connectivity.Ready {
		t.Errorf("state after IsConnected %v, want READY", s)
	}
}

func TestAChannelToNoBessIsDown(t *testing.T) {
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := lis.Addr().String()
	_ = lis.Close()

	conn, err := grpc.NewClient(addr, bessDialOptions()...)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	b := &bess{conn: conn}
	if b.IsConnected(nil) {
		t.Error("a channel to a closed port is reported up")
	}

	if (&bess{}).IsConnected(nil) {
		t.Error("no channel is reported up")
	}
}
