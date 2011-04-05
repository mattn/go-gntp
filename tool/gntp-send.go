package main

import (
	"gntp"
	"flag"
	"fmt"
	"os"
)

func main() {
	server := flag.String("s", "localhost:23053", "growl server(host:port)")
	password := flag.String("p", "", "password")
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "usage: gntp-send [-s=server] [-p=password] title message [icon] [url]\n")
		flag.PrintDefaults()
		return
	}
	title := flag.Arg(0)
	message := flag.Arg(1)
	icon := flag.Arg(2)
	url := flag.Arg(3)
	client := gntp.NewClient()
	client.SetAppName("gntp-send")
	client.SetServer(*server)
	client.SetPassword(*password)
	err := client.Register()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.String())
		return
	}
	err = client.Notify(title, message, icon, url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.String())
		return
	}
}
