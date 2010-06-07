package gntp;

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"rand"
	"strings"
)

type client struct {
	server string;
	password string;
	appName string;
}

func (c *client) send(method string, stm string) ([]byte, os.Error) {
	conn, err := net.Dial("tcp", "", c.server);
	if err != nil {
		return nil, err
	}
	if len(c.password) > 0 {
		salt := make([]byte, 8);
		for n := 0; n < len(salt); n++ {
			salt[n] = uint8(rand.Int() % 256);
		}
		d := md5.New()
		d.Write([]byte(c.password))
		d.Write(salt);
		hash := d.Sum();
		d.Reset();
		d.Write(hash);
		s := fmt.Sprintf("%x.%x", d.Sum(), salt)
		conn.Write([]byte(
			"GNTP/1.0 " + method + " NONE MD5:" + s + "\r\n" + stm + "\r\n"));
	} else {
		conn.Write([]byte(
			"GNTP/1.0 " + method + " NONE\r\n" + stm + "\r\n"));
	}
	return ioutil.ReadAll(conn);
}

func NewClient() *client {
	return &client { "localhost:23053", "", "go-gntp-send" };
}

func NewClientWithPassword(password string) *client {
	return &client { "localhost:23053", password, "go-gntp-send" };
}

func (c *client) SetServer(server string) {
	c.server = server;
}

func (c *client) SetPassword(password string) {
	c.password = password;
}

func (c *client) SetAppName(appName string) {
	c.appName = appName;
}

func (c *client) Register() os.Error {
	b, err := c.send("REGISTER",
		"Application-Name: " + c.appName + "\r\n" +
		"Notifications-Count: 1\r\n" +
		"\r\n" +
		"Notification-Name: go-gntp-notify\r\n" +
		"Notification-Display-Name: go-gntp-notify\r\n" +
		"Notification-Enabled: True\r\n" +
		"\r\n");
	if err == nil {
		res := string(b);
		if res[0:15] == "GNTP/1.0 -ERROR" {
			lines := strings.Split(res, "\r\n", 200)
			for n := range lines {
				if len(lines[n]) > 18 && lines[n][0:18] == "Error-Description:" {
					err = os.NewError(lines[n][19:]);
					break;
				}
			}
		}
	}
	return err;
}

func (c *client) Notify(title string, text string, icon string, callback string) os.Error {
	b, err := c.send("NOTIFY",
		"Application-Name: " + c.appName + "\r\n" +
		"Notification-Name: go-gntp-notify\r\n" +
		"Notification-Title: " + title + "\r\n" +
		"Notification-Text: " + text + "\r\n" +
		"Notification-Icon: " + icon + "\r\n" +
		"Notification-Callback-Target: " + callback + "\r\n" +
		"\r\n");
	if err == nil {
		res := string(b);
		if res[0:15] == "GNTP/1.0 -ERROR" {
			lines := strings.Split(res, "\r\n", 200)
			for n := range lines {
				if len(lines[n]) > 18 && lines[n][0:18] == "Error-Description:" {
					err = os.NewError(lines[n][19:]);
					break;
				}
			}
		}
	}
	return err;
}
