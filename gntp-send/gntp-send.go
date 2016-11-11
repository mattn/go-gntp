package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-gntp"
)

const DefaultNotifyName = "default"

func main() {
	server := flag.String("s", "localhost:23053", "growl server(host:port)")
	appname := flag.String("a", "gntp-send", "application")
	noRegister := flag.Bool("nr", false, "no register")
	hashAlgorithm := flag.String("ha", "SHA256", "hash algorithm")
	encryptAlgorithm := flag.String("ea", "AES", "encrypt algorithm")
	displayName := flag.String("d", "", "display name")
	sticky := flag.Bool("t", false, "sticky")
	password := flag.String("p", "", "password")
	event := flag.String("e", DefaultNotifyName, "event")
	readStdin := flag.Bool("i", false, "read from stdin")
	flag.Parse()
	if !*readStdin && flag.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "usage: gntp-send [options] title message [icon] [url]\n")
		flag.PrintDefaults()
		return
	}
	var title, message, icon, url string
	if *readStdin {
		stdin := bufio.NewReader(os.Stdin)
		title, _ = stdin.ReadString('\n')
		message, _ = stdin.ReadString(0)
		title = strings.TrimSpace(title)
		message = strings.TrimSpace(message)
		icon = flag.Arg(0)
		url = flag.Arg(1)
	} else {
		title = flag.Arg(0)
		message = flag.Arg(1)
		icon = flag.Arg(2)
		url = flag.Arg(3)
	}

	client := gntp.NewClient()
	client.AppName = *appname
	client.Server = *server
	client.Password = *password
	client.HashAlgorithm = *hashAlgorithm
	client.EncryptAlgorithm = *encryptAlgorithm

	n := []gntp.Notification{{DefaultNotifyName, *displayName, true}}
	if *event != DefaultNotifyName {
		n = append(n, gntp.Notification{*event, *event, true})
	}
	var err error
	if *noRegister == false {
		err = client.Register(n)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
	err = client.Notify(&gntp.Message{
		Event:       *event,
		Title:       title,
		Text:        message,
		Icon:        icon,
		Callback:    url,
		DisplayName: *displayName,
		Sticky:      *sticky,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}
