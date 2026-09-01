package main

import (
	"context"
	"net"
)

func baseContext(root context.Context) func(net.Listener) context.Context {
	return func(_ net.Listener) context.Context { return root }
}
