package radius

import "sync"

// NewClientList returns a ClientList initialized with cs.
func NewClientList(cs []Client) *ClientList {
	cl := new(ClientList)
	cl.SetHerd(cs)
	return cl
}

// ClientList is a concurrency-safe set of RADIUS clients indexed by host.
type ClientList struct {
	herd map[string]Client
	sync.RWMutex
}

// Get returns a client by host, or nil if not present.
func (cls *ClientList) Get(host string) Client {
	cls.RLock()
	defer cls.RUnlock()
	cl, _ := cls.herd[host]
	return cl
}

// AddOrUpdate adds a new client or replaces an existing client with the same host.
func (cls *ClientList) AddOrUpdate(cl Client) {
	cls.Lock()
	defer cls.Unlock()
	cls.herd[cl.GetHost()] = cl
}

// Remove deletes a client by host.
func (cls *ClientList) Remove(host string) {
	cls.Lock()
	defer cls.Unlock()
	delete(cls.herd, host)
}

// SetHerd replaces the current client set with herd.
func (cls *ClientList) SetHerd(herd []Client) {
	cls.Lock()
	defer cls.Unlock()
	if cls.herd == nil {
		cls.herd = make(map[string]Client)
	}
	for _, v := range herd {
		cls.herd[v.GetHost()] = v
	}
}

// GetHerd returns a snapshot of the current clients.
func (cls *ClientList) GetHerd() []Client {
	cls.RLock()
	defer cls.RUnlock()
	herd := make([]Client, len(cls.herd))
	i := 0
	for _, v := range cls.herd {
		herd[i] = v
		i++
	}
	return herd
}

// Client represents a RADIUS peer with a host and a shared secret.
type Client interface {
	// GetHost get the client host
	GetHost() string
	// GetSecret get shared secret
	GetSecret() string
}

// NewClient returns a default Client implementation for the given host and secret.
func NewClient(host, secret string) Client {
	return &DefaultClient{host, secret}
}

// DefaultClient is the default Client implementation.
type DefaultClient struct {
	Host   string
	Secret string
}

// GetSecret returns the client's shared secret.
func (cl *DefaultClient) GetSecret() string {
	return cl.Secret
}

// GetHost returns the client's host.
func (cl *DefaultClient) GetHost() string {
	return cl.Host
}
