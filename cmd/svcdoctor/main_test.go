package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestSignalsReachTheDeliveryChannel proves the wiring half of ADR 0073
// section 7.2: a real interrupt sent to this process arrives on a channel
// created and registered exactly as main creates and registers its own.
//
// It sends a real signal, which is safe: the channel is local to this test,
// signal.Notify redirects delivery to it, and signal.Stop restores the default
// disposition before the test returns.
func TestSignalsReachTheDeliveryChannel(t *testing.T) {
	signals := make(chan os.Signal, interruptBuffer)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	if err := self.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("sending an interrupt: %v", err)
	}

	select {
	case <-signals:
	case <-time.After(5 * time.Second):
		t.Fatal("the interrupt was never delivered")
	}
}

// TestTheDeliveryChannelHoldsBothStages pins the buffer size.
//
// # What the buffer is for, stated exactly
//
// os/signal **drops** a signal rather than blocking when the delivery channel is
// full. The window that matters is the one where the watcher goroutine is inside
// stage one — running cancel() — and a second interrupt arrives. With a
// single-slot channel already holding the first signal, that second one would be
// discarded, and it is the only one that can force a run to stop.
//
// So this asserts what the buffer guarantees: two signals can be queued without
// a receiver, which is the state the watcher is in between its two selects.
//
// # What this deliberately does not do, and why
//
// The obvious version sends two real SIGINTs and expects two deliveries. It
// fails, and it fails for a reason outside svcdoctor: POSIX coalesces a
// non-realtime signal that is already pending, so two SIGINTs raised before the
// runtime has dequeued the first arrive as one. That is a property of the
// operating system, not of this channel, and it was measured here rather than
// assumed.
//
// It does not weaken the contract. Coalescing only happens while a signal sits
// undelivered, the Go runtime dequeues promptly, and the interval between two
// deliberate Ctrl-C presses is many orders of magnitude larger than that window.
// A buffer of two is still what keeps the second one from being dropped once it
// has been delivered.
func TestTheDeliveryChannelHoldsBothStages(t *testing.T) {
	if interruptBuffer < 2 {
		t.Fatalf("interruptBuffer = %d; the contract has two stages and os/signal "+
			"drops a signal when the channel is full", interruptBuffer)
	}

	signals := make(chan os.Signal, interruptBuffer)
	for i := range 2 {
		select {
		case signals <- syscall.SIGINT:
		default:
			t.Fatalf("the delivery channel refused signal %d with no receiver "+
				"running; a second interrupt would be dropped", i+1)
		}
	}
}
