package radius

import "sync"

// pool is a typed wrapper around sync.Pool.
type pool[T any] struct {
	p sync.Pool
}

func newPool[T any](newFn func() T) *pool[T] {
	return &pool[T]{p: sync.Pool{New: func() any { return newFn() }}}
}

func (p *pool[T]) Get() T  { return p.p.Get().(T) }
func (p *pool[T]) Put(x T) { p.p.Put(x) }
