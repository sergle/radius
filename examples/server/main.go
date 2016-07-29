package main

import (
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "log"
    "time"

    "github.com/sergle/radius"
)

type radiusService struct{}

var cnt int = 0
var dict *radius.Dictionary

func (p radiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
    // a pretty print of the request.
    fmt.Printf("%d [Authenticate] %s\n", cnt, request.String())

    for _, avp := range request.AVPs {
        fmt.Printf("AVP: %#v\n", avp)
        attr_name := dict.GetAttributeName(avp.Type)
        attr_type := dict.GetAttributeType(attr_name)
        fmt.Printf("  name: %s type: %s value: %s\n", attr_name, attr_type, dict.DecodeAVPValue(request, avp))
    }

    time.Sleep(100 * time.Millisecond)
    cnt = cnt + 1
    npac := request.Reply()
    switch request.Code {
    case radius.AccessRequest:
        // check username and password
        if request.GetUsername() == "a" && request.GetPassword() == "a" {
            npac.Code = radius.AccessAccept
            npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.ReplyMessage, Value: []byte("All OK!")})
            fmt.Printf("Reply: %s\n", npac.String())
            return npac
        } else {
            npac.Code = radius.AccessReject
            npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.ReplyMessage, Value: []byte("you dick!")})
            fmt.Printf("Reply: %s\n", npac.String())
            return npac
        }
    case radius.AccountingRequest:
        // accounting start or end
        npac.Code = radius.AccountingResponse
        return npac
    case radius.DisconnectRequest:
        npac.Code = radius.DisconnectAccept
        npac.AddAVP( dict.NewAVP("Reply-Message", "Session disconnected") )
        npac.AddVSA( dict.NewVSA("Cisco", "h323-remote-address", "10.20.30.41") )
        fmt.Printf("Reply: %s\n", npac.String())
        return npac
    default:
        npac.Code = radius.AccessAccept
        fmt.Printf("Reply: %s\n", npac.String())
        return npac
    }
}

func main() {
    dict = radius.NewDictionary()
    err := dict.LoadFile("/usr/share/freeradius/dictionary")
    if err != nil {
        fmt.Printf("Failed to load dictionary: %s", err)
        return
    }

    s := radius.NewServer("127.0.0.1:1812", "gopher", radiusService{})

    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
    errChan := make(chan error)

    go func() {
        fmt.Println("waiting for packets on 127.0.0.1:1812 ...")
        err := s.ListenAndServe()
        if err != nil {
            errChan <- err
        }
    }()

    select {
        case <-signalChan:
            log.Println("stopping server...")
            s.Stop()
        case err := <-errChan:
            log.Println("[ERR] %v", err.Error())
    }
}
