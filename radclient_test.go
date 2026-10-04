package radius

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// startLegacyServer answers every request with an Access-Accept that has no Message-Authenticator.
func startLegacyServer(t *testing.T, secret string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, maxPacketLen)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < packetHeaderLen {
				continue
			}
			reply := make([]byte, packetHeaderLen)
			reply[0] = byte(AccessAccept)
			reply[1] = buf[1]
			binary.BigEndian.PutUint16(reply[2:4], packetHeaderLen)
			h := md5.New()
			h.Write(reply[:4])
			h.Write(buf[4:packetHeaderLen])
			h.Write([]byte(secret))
			copy(reply[4:], h.Sum(nil))
			conn.WriteToUDP(reply, addr)
		}
	}()
	return conn.LocalAddr().String()
}

// Blast-RADIUS: RadClient rejects Access-* replies without Message-Authenticator unless opted out.
func TestRadClientRequiresMessageAuthenticator(t *testing.T) {
	const secret = "testing123"
	client := NewRadClient(startLegacyServer(t, secret), secret)
	client.SetTimeout(100 * time.Millisecond)

	if _, err := client.Send(client.NewAccessRequest()); !errors.Is(err, ErrMessageAuthenticatorMissing) {
		t.Fatalf("default: got %v, want %v", err, ErrMessageAuthenticatorMissing)
	}

	client.SetRequireMessageAuthenticator(false)
	reply, err := client.Send(client.NewAccessRequest())
	if err != nil {
		t.Fatalf("opted out: %v", err)
	}
	if reply.Code != AccessAccept {
		t.Fatalf("opted out: got %v, want Access-Accept", reply.Code)
	}
}

// startScriptedServer calls respond for each received request (attempt counts from 1) and sends back what it returns.
func startScriptedServer(t *testing.T, respond func(attempt int, req []byte) [][]byte) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, maxPacketLen)
		for attempt := 1; ; attempt++ {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			for _, b := range respond(attempt, append([]byte(nil), buf[:n]...)) {
				conn.WriteToUDP(b, addr)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// acceptReply builds a valid Access-Accept for req.
func acceptReply(t *testing.T, secret string, req []byte) []byte {
	t.Helper()
	p, err := DecodeRequest(secret, req)
	if err != nil {
		t.Errorf("decode request: %v", err)
		return nil
	}
	b, err := p.ReplyAccept().Encode()
	if err != nil {
		t.Errorf("encode reply: %v", err)
		return nil
	}
	return b
}

// A dropped request is retransmitted with identical bytes and the reply to it is accepted.
func TestRadClientRetransmit(t *testing.T) {
	const secret = "testing123"
	reqs := make(chan []byte, 4)
	addr := startScriptedServer(t, func(attempt int, req []byte) [][]byte {
		reqs <- req
		if attempt == 1 {
			return nil // drop
		}
		return [][]byte{acceptReply(t, secret, req)}
	})
	client := NewRadClient(addr, secret)
	client.SetTimeout(5 * time.Second)
	client.SetRetries(2)
	client.SetRetryInterval(50 * time.Millisecond)

	reply, err := client.Send(client.NewAccessRequest())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if reply.Code != AccessAccept {
		t.Fatalf("got %v, want Access-Accept", reply.Code)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	if first, second := <-reqs, <-reqs; !bytes.Equal(first, second) {
		t.Fatal("retransmission differs from original request")
	}
}

// Without retries the request is sent once and times out.
func TestRadClientNoRetriesByDefault(t *testing.T) {
	const secret = "testing123"
	var attempts atomic.Int32
	addr := startScriptedServer(t, func(attempt int, req []byte) [][]byte {
		attempts.Store(int32(attempt))
		return nil
	})
	client := NewRadClient(addr, secret)
	client.SetTimeout(100 * time.Millisecond)

	_, err := client.Send(client.NewAccessRequest())
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("got %v, want timeout", err)
	}
	if n := attempts.Load(); n != 1 {
		t.Fatalf("got %d requests, want 1", n)
	}
}

// Retransmissions stop after the configured retry count.
func TestRadClientRetriesExhausted(t *testing.T) {
	const secret = "testing123"
	var attempts atomic.Int32
	addr := startScriptedServer(t, func(attempt int, req []byte) [][]byte {
		attempts.Store(int32(attempt))
		return nil
	})
	client := NewRadClient(addr, secret)
	client.SetTimeout(300 * time.Millisecond)
	client.SetRetries(2)
	client.SetRetryInterval(20 * time.Millisecond)

	if _, err := client.Send(client.NewAccessRequest()); err == nil {
		t.Fatal("expected error")
	}
	if n := attempts.Load(); n != 3 {
		t.Fatalf("got %d requests, want 3", n)
	}
}

// Stray replies (wrong Identifier, bad authenticator, garbage) are skipped while waiting for the real one.
func TestRadClientSkipsStrayReplies(t *testing.T) {
	const secret = "testing123"
	addr := startScriptedServer(t, func(attempt int, req []byte) [][]byte {
		good := acceptReply(t, secret, req)
		wrongID := append([]byte(nil), good...)
		wrongID[1]++
		badAuth := append([]byte(nil), good...)
		badAuth[4] ^= 0xff
		return [][]byte{{0x01}, wrongID, badAuth, good}
	})
	client := NewRadClient(addr, secret)
	client.SetTimeout(time.Second)

	reply, err := client.Send(client.NewAccessRequest())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if reply.Code != AccessAccept {
		t.Fatalf("got %v, want Access-Accept", reply.Code)
	}
}

// A context deadline bounds retransmissions.
func TestRadClientContextDeadline(t *testing.T) {
	const secret = "testing123"
	addr := startScriptedServer(t, func(attempt int, req []byte) [][]byte { return nil })
	client := NewRadClient(addr, secret)
	client.SetRetries(100)
	client.SetRetryInterval(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := client.SendContext(ctx, client.NewAccessRequest()); err == nil {
		t.Fatal("expected error")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v, want about 100ms", d)
	}
}

// Cancelling a context without a deadline aborts the wait.
func TestRadClientContextCancel(t *testing.T) {
	const secret = "testing123"
	received := make(chan struct{}, 1)
	addr := startScriptedServer(t, func(attempt int, req []byte) [][]byte {
		received <- struct{}{}
		return nil
	})
	client := NewRadClient(addr, secret)
	client.SetTimeout(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-received
		cancel()
	}()
	start := time.Now()
	if _, err := client.SendContext(ctx, client.NewAccessRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want %v", err, context.Canceled)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v, want prompt return", d)
	}
}

// Without a retry interval a silent server gets one request and the whole timeout to answer.
func TestRadClientNoIntervalWaitsFullTimeout(t *testing.T) {
	const secret = "testing123"
	var attempts atomic.Int32
	addr := startScriptedServer(t, func(attempt int, req []byte) [][]byte {
		attempts.Store(int32(attempt))
		return nil
	})
	client := NewRadClient(addr, secret)
	client.SetTimeout(200 * time.Millisecond)
	client.SetRetries(3)

	_, err := client.Send(client.NewAccessRequest())
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("got %v, want timeout", err)
	}
	// let the server read any retransmission still queued
	time.Sleep(noReplyTimeout)
	if n := attempts.Load(); n != 1 {
		t.Fatalf("got %d requests, want 1", n)
	}
}

// closedUDPAddr returns a local address with no listener: sends to it fail with ECONNREFUSED.
func closedUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()
	return addr
}

// Errors are retried with exponential backoff; the last error is returned.
func TestRadClientRetryBackoff(t *testing.T) {
	client := NewRadClient(closedUDPAddr(t), "testing123")
	client.SetTimeout(5 * time.Second)
	client.SetRetries(2)

	start := time.Now()
	if _, err := client.Send(client.NewAccessRequest()); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("got %v, want %v", err, syscall.ECONNREFUSED)
	}
	// two backoffs: retryBackoff, then 2*retryBackoff
	if d, want := time.Since(start), 3*retryBackoff; d < want || d > want+time.Second {
		t.Fatalf("took %v, want about %v", d, want)
	}
}

// Backoff never waits past the deadline.
func TestRadClientRetryBackoffDeadline(t *testing.T) {
	client := NewRadClient(closedUDPAddr(t), "testing123")
	client.SetTimeout(retryBackoff / 2)
	client.SetRetries(3)

	start := time.Now()
	if _, err := client.Send(client.NewAccessRequest()); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("got %v, want %v", err, syscall.ECONNREFUSED)
	}
	if d := time.Since(start); d >= retryBackoff {
		t.Fatalf("took %v, want less than %v", d, retryBackoff)
	}
}

// A server that comes up during the backoff answers the retransmission.
func TestRadClientRetryAfterServerStarts(t *testing.T) {
	const secret = "testing123"
	addr := closedUDPAddr(t)
	client := NewRadClient(addr, secret)
	client.SetTimeout(5 * time.Second)
	client.SetRetries(3)

	type result struct {
		reply *Packet
		err   error
	}
	done := make(chan result, 1)
	go func() {
		reply, err := client.Send(client.NewAccessRequest())
		done <- result{reply, err}
	}()

	// start within the first backoff
	time.Sleep(retryBackoff / 2)
	uaddr, _ := net.ResolveUDPAddr("udp", addr)
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		t.Skipf("port reused: %v", err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, maxPacketLen)
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		conn.WriteToUDP(acceptReply(t, secret, buf[:n]), raddr)
	}()

	r := <-done
	if r.err != nil {
		t.Fatalf("send: %v", r.err)
	}
	if r.reply.Code != AccessAccept {
		t.Fatalf("got %v, want Access-Accept", r.reply.Code)
	}
}
