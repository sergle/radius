package radius

import (
	"encoding/binary"
	"math"
	"strconv"
	"time"
)

// dateLen is the size of a "date" value, seconds since the Unix epoch.
const dateLen = 4

var avpDate AvpDate

// AvpDate handles "date" attributes, e.g. Event-Timestamp; Value returns a UTC time.Time.
type AvpDate struct{}

func (s AvpDate) Value(p *Packet, a AVP) any {
	if len(a.Value) != dateLen {
		return time.Time{}
	}
	return time.Unix(int64(binary.BigEndian.Uint32(a.Value)), 0).UTC()
}

// String formats the value as RFC 3339 in UTC.
func (s AvpDate) String(p *Packet, a AVP) string {
	if len(a.Value) != dateLen {
		return avpBinary.String(p, a)
	}
	return s.Value(p, a).(time.Time).Format(time.RFC3339)
}

// FromString parses seconds since the epoch or an RFC 3339 time, or returns nil.
func (s AvpDate) FromString(v string) []byte {
	secs, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil
		}
		secs = t.Unix()
	}
	if secs < 0 || secs > math.MaxUint32 {
		return nil
	}
	return binary.BigEndian.AppendUint32(nil, uint32(secs))
}
