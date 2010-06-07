package main;

import (
	"gntp"
	"flag"
	"fmt"
	"os"
)

func main() {
	server := flag.String("s", "localhost:23053", "growl server(host:port)");
	password := flag.String("p", "", "password");
	title := flag.String("t", "", "title text");
	text := flag.String("m", "", "message text");
	icon := flag.String("i", "", "icon url");
	callback := flag.String("u", "", "callback url");
	flag.Parse();
	if len(*title) == 0 || len(*text) == 0 {
		flag.Usage();
		return;
	}
	client := gntp.NewClient();
	client.SetServer(*server);
	client.SetPassword(*password);
	err := client.Register();
	if err != nil {
		fmt.Fprintln(os.Stderr, err.String());
		return;
	}
	err = client.Notify(*title, *text, *icon, *callback);
	if err != nil {
		fmt.Fprintln(os.Stderr, err.String());
		return;
	}
}
