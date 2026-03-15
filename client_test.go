package radius

import (
	"reflect"
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
