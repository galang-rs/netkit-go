package js

import (
	"context"
	"net"
	"time"

	"github.com/bacot120211/netkit-go/pkg/engine"
)

// RegisterDNSModule injects ctx.DNS into the JS context.
func RegisterDNSModule(jsCtx map[string]interface{}) {
	resolver := &net.Resolver{
		PreferGo: true,
	}

	jsCtx["DNS"] = map[string]interface{}{
		// Lookup resolves A/AAAA records for a hostname.
		"Lookup": func(host string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			addrs, err := resolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			return addrs, nil
		},
		// LookupIP resolves only IPv4 or IPv6 addresses.
		// network: "ip4" or "ip6"
		"LookupIP": func(network, host string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var result []string
			for _, ip := range ips {
				if network == "ip4" && ip.IP.To4() != nil {
					result = append(result, ip.IP.String())
				} else if network == "ip6" && ip.IP.To4() == nil {
					result = append(result, ip.IP.String())
				} else if network == "" {
					result = append(result, ip.IP.String())
				}
			}
			return result, nil
		},
		// Reverse performs a reverse DNS lookup (PTR).
		"Reverse": func(ip string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			names, err := resolver.LookupAddr(ctx, ip)
			if err != nil {
				return nil, err
			}
			return names, nil
		},
		// ResolveMX resolves MX records.
		"ResolveMX": func(domain string) ([]map[string]interface{}, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			mxs, err := resolver.LookupMX(ctx, domain)
			if err != nil {
				return nil, err
			}
			var result []map[string]interface{}
			for _, mx := range mxs {
				result = append(result, map[string]interface{}{
					"host": mx.Host,
					"pref": mx.Pref,
				})
			}
			return result, nil
		},
		// ResolveTXT resolves TXT records.
		"ResolveTXT": func(domain string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return resolver.LookupTXT(ctx, domain)
		},
		// ResolveNS resolves NS records.
		"ResolveNS": func(domain string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			nss, err := resolver.LookupNS(ctx, domain)
			if err != nil {
				return nil, err
			}
			var result []string
			for _, ns := range nss {
				result = append(result, ns.Host)
			}
			return result, nil
		},
		// ResolveCNAME resolves CNAME records.
		"ResolveCNAME": func(domain string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return resolver.LookupCNAME(ctx, domain)
		},
		// ResolveSRV resolves SRV records.
		"ResolveSRV": func(service, proto, name string) ([]map[string]interface{}, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, srvs, err := resolver.LookupSRV(ctx, service, proto, name)
			if err != nil {
				return nil, err
			}
			var result []map[string]interface{}
			for _, srv := range srvs {
				result = append(result, map[string]interface{}{
					"target":   srv.Target,
					"port":     srv.Port,
					"priority": srv.Priority,
					"weight":   srv.Weight,
				})
			}
			return result, nil
		},
		// LookupPort resolves the port for a service/network (e.g., "tcp", "http").
		"LookupPort": func(network, service string) (int, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return resolver.LookupPort(ctx, network, service)
		},
	}
}

// RegisterAsyncDNS injects async DNS methods that need engine/packet context.
func RegisterAsyncDNS(jsCtx map[string]interface{}, eng engine.Engine, pkt *engine.Packet) {
	dns, ok := jsCtx["DNS"].(map[string]interface{})
	if !ok {
		return
	}

	resolver := &net.Resolver{PreferGo: true}

	dns["AsyncPTR"] = func(ip string) {
		// Get current reference
		var ref string
		if pkt.Metadata != nil {
			if r, ok := pkt.Metadata["Reference"].(string); ok {
				ref = r
			}
		}

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			names, err := resolver.LookupAddr(ctx, ip)
			domain := ""
			if err == nil && len(names) > 0 {
				domain = names[0]
			}

			// Ingest synthetic packet back into engine
			respPkt := &engine.Packet{
				ID:        uint64(time.Now().UnixNano()),
				Timestamp: time.Now().Unix(),
				Source:    "dns-resolver",
				Protocol:  "DNS-PTR",
				Metadata: map[string]interface{}{
					"IsPtrResponse": true,
					"Reference":     ref,
					"IP":            ip,
					"Domain":        domain,
				},
			}
			eng.Ingest(respPkt)
		}()
	}
}
