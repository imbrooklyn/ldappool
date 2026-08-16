package ldappool

import (
	"context"
	"fmt"
	"net"
	"testing"
)

func BenchmarkHotAcquireRelease(b *testing.B) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	config := anonymousTestConfig(dialer)
	config.MaxOpen = 1
	config.MaxIdle = 1
	pool, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	if err := pool.Warmup(context.Background(), 1); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pool.WithConnection(context.Background(), func(*Connection) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = pool.Close(context.Background())
}

func BenchmarkSnapshot(b *testing.B) {
	dialer := &testDialer{factory: pipeFactory(successfulLDAPServer, nil)}
	pool, err := New(anonymousTestConfig(dialer))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pool.Snapshot()
	}
	b.StopTimer()
	_ = pool.Close(context.Background())
}

func BenchmarkContendedAcquireRelease(b *testing.B) {
	for _, maxOpen := range []int{1, 8, 64} {
		b.Run(fmt.Sprintf("max_open_%d", maxOpen), func(b *testing.B) {
			dialer := &testDialer{factory: func(_ context.Context, call int) (net.Conn, error) {
				client, server := net.Pipe()
				go successfulLDAPServer(server, call)
				return client, nil
			}}
			config := anonymousTestConfig(dialer)
			config.MaxOpen = maxOpen
			config.MaxIdle = maxOpen
			config.MaxWaiters = 4096
			pool, err := New(config)
			if err != nil {
				b.Fatal(err)
			}
			if err := pool.Warmup(context.Background(), maxOpen); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := pool.WithConnection(context.Background(), func(*Connection) error { return nil }); err != nil {
						b.Error(err)
						return
					}
				}
			})
			b.StopTimer()
			_ = pool.Close(context.Background())
		})
	}
}
