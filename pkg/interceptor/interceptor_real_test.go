package interceptor

import (
	"testing"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

func TestInterceptorReal_Metadata(t *testing.T) {
	e := engine.New()
	ti := NewTransparentInterceptor(e)

	// 1. Test OnPacket Metadata tagging (Integration with JS hooks)
	ctx := &engine.PacketContext{
		Packet: &engine.Packet{
			Payload: []byte("Some Data"),
		},
	}

	err := ti.OnPacket(ctx)
	if err != nil {
		t.Fatalf("OnPacket failed: %v", err)
	}

	if ctx.Packet.Metadata["Transparent"] != true {
		t.Errorf("Metadata 'Transparent' not set correctly by interceptor")
	}
	t.Logf("Transparent Interceptor metadata tagging verified for JS integration!")
}
