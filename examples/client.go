package main

import (
    "fmt"

    "github.com/sergle/radius"
    "github.com/sergle/radius/client"
)

func main() {
    dict := radius.NewDictionary()
    err := dict.LoadFile("/usr/share/freeradius/dictionary")
    if err != nil {
        fmt.Printf("Failed to load dictionary: %s", err)
        return
    }

    client := client.NewClient("127.0.0.1:1812", "gother")

    // FIXME no support yet for Password encoding
    //request := client.NewRequest(radius.AccessRequest)
    // request.AddAVP( dict.NewAVP("User-Name", "a") )
    //request.AddAVP( dict.NewAVP("User-Password", "a") )

    request := client.NewRequest(radius.DisconnectRequest)
    request.AddAVP( dict.NewAVP("Acct-Session-Id", "100500") )
    request.AddAVP( dict.NewAVP("NAS-IP-Address", "10.8.10.3") )
    fmt.Printf("sending request: %s\n", request.String())

    reply, err := client.Send(request)
    if err != nil {
        fmt.Printf("Error: %s\n", err)
        return
    }

    fmt.Printf("Reply: %s\n", reply.String())

    return
}
