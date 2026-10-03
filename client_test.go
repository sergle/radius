package radius

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestClientList(t *testing.T) {
	herd := []Client{
		NewClient("1.1.1.1", "secret1"),
		NewClient("2.2.2.2", "secret2"),
	}
	cls := NewClientList(herd)

	if len(cls.GetHerd()) != len(herd) {
		t.Error("GetHerd length failure")
	}
	for _, c := range herd {
		if !reflect.DeepEqual(cls.Get(c.GetHost()), c) {
			t.Errorf("Get failure for %s", c.GetHost())
		}
	}

	newClient := NewClient("3.3.3.3", "secret3")
	cls.AddOrUpdate(newClient)
	if !reflect.DeepEqual(cls.Get("3.3.3.3"), newClient) {
		t.Error("Get failure after AddOrUpdate")
	}
	if len(cls.GetHerd()) != 3 {
		t.Errorf("Expected 3 clients, got %d", len(cls.GetHerd()))
	}

	updateClient := NewClient("1.1.1.1", "updatesecret")
	cls.AddOrUpdate(updateClient)
	if !reflect.DeepEqual(cls.Get("1.1.1.1"), updateClient) {
		t.Error("Get failure after update")
	}
	if len(cls.GetHerd()) != 3 {
		t.Errorf("Expected 3 clients, got %d", len(cls.GetHerd()))
	}

	cls.Remove("3.3.3.3")
	if cls.Get("3.3.3.3") != nil {
		t.Error("Get should return nil after Remove")
	}
	if len(cls.GetHerd()) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(cls.GetHerd()))
	}
}

func TestClientListZeroValue(t *testing.T) {
	var cls ClientList
	if cls.Get("1.1.1.1") != nil || len(cls.GetHerd()) != 0 {
		t.Fatal("zero-value ClientList should be empty")
	}
	cls.Remove("1.1.1.1")

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("AddOrUpdate on zero-value ClientList panicked: %v", r)
			}
		}()
		cls.AddOrUpdate(NewClient("1.1.1.1", "secret1"))
	}()
	if c := cls.Get("1.1.1.1"); c == nil || c.GetSecret() != "secret1" {
		t.Errorf("Get after AddOrUpdate = %v", c)
	}
}

func TestClientListSetHerdReplaces(t *testing.T) {
	cls := NewClientList([]Client{
		NewClient("1.1.1.1", "secret1"),
		NewClient("2.2.2.2", "secret2"),
	})
	cls.SetHerd([]Client{
		NewClient("2.2.2.2", "new2"),
		NewClient("3.3.3.3", "secret3"),
	})

	if c := cls.Get("1.1.1.1"); c != nil {
		t.Errorf("1.1.1.1 should be gone after SetHerd, got %v", c)
	}
	if c := cls.Get("2.2.2.2"); c == nil || c.GetSecret() != "new2" {
		t.Errorf("2.2.2.2 = %v, want secret new2", c)
	}
	if c := cls.Get("3.3.3.3"); c == nil || c.GetSecret() != "secret3" {
		t.Errorf("3.3.3.3 = %v, want secret secret3", c)
	}

	got := map[string]string{}
	for _, c := range cls.GetHerd() {
		got[c.GetHost()] = c.GetSecret()
	}
	want := map[string]string{"2.2.2.2": "new2", "3.3.3.3": "secret3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetHerd = %v, want %v", got, want)
	}
}

func TestClientListConcurrent(t *testing.T) {
	var cls ClientList
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("10.0.0.%d", i)
			for j := 0; j < 100; j++ {
				cls.AddOrUpdate(NewClient(host, "s"))
				cls.Get(host)
				cls.GetHerd()
				cls.SetHerd([]Client{NewClient(host, "s")})
				cls.Remove(host)
			}
		}(i)
	}
	wg.Wait()
}
