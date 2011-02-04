package gntp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	//"crypto/aes"
	"fmt"
	"hash"
	"io/ioutil"
	"net"
	"os"
	"rand"
	"strings"
)

type client struct {
	server           string
	password         string
	appName          string
	hashAlgorithm    string
	encryptAlgorithm string
}

func (c *client) send(method string, stm string) (ret []byte, err os.Error) {
	conn, err := net.Dial("tcp", "", c.server)
	if err != nil {
		return nil, err
	}
	if len(c.password) > 0 {
		salt := make([]byte, 8)
		for n := 0; n < len(salt); n++ {
			salt[n] = uint8(rand.Int() % 256)
		}
		var ha hash.Hash
		switch c.hashAlgorithm {
		case "MD5":
			ha = md5.New()
		case "SHA1":
			ha = sha1.New()
		case "SHA256":
			ha = sha256.New()
		default:
			return nil, os.NewError("unknown hash algorithm")
		}
		ha.Write([]byte(c.password))
		ha.Write(salt)
		hv := ha.Sum()
		ha.Reset()
		ha.Write(hv)
		hs := fmt.Sprintf("%x.%x", ha.Sum(), salt)

		/*
			in := ([]byte)(stm)
			out := make([]byte, len(in))
			switch c.encryptAlgorithm {
			case "AES":
				hv = hv[0:24]
				ci, err := aes.NewCipher(hv)
				if err != nil {
					ci.Encrypt(out, in)
				}
			case "NONE":
				out = in
			default:
				panic("unknown encrypt algorithm")
			}
		*/

		conn.Write([]byte(
			"GNTP/1.0 " + method + " " + c.encryptAlgorithm + " " + c.hashAlgorithm + ":" + hs + "\r\n"))
		conn.Write([]byte(stm))
		conn.Write([]byte("\r\n"))
	} else {
		conn.Write([]byte(
			"GNTP/1.0 " + method + " NONE\r\n" + stm + "\r\n"))
	}
	return ioutil.ReadAll(conn)
}

func NewClient() *client {
	return &client{"localhost:23053", "", "go-gntp-send", "MD5", "NONE"}
}

func NewClientWithPassword(password string) *client {
	return &client{"localhost:23053", password, "go-gntp-send", "MD5", "NONE"}
}

func (c *client) SetServer(server string) {
	c.server = server
}

func (c *client) SetPassword(password string) {
	c.password = password
}

func (c *client) SetAppName(appName string) {
	c.appName = appName
}

func (c *client) SetEncryptAlgorithm(encryptAlgorithm string) {
	c.encryptAlgorithm = encryptAlgorithm
}

func (c *client) SetHashAlgorithm(hashAlgorithm string) {
	c.hashAlgorithm = hashAlgorithm
}

func (c *client) Register() os.Error {
	b, err := c.send("REGISTER",
		"Application-Name: "+c.appName+"\r\n"+
			"Notifications-Count: 1\r\n"+
			"\r\n"+
			"Notification-Name: go-gntp-notify\r\n"+
			"Notification-Display-Name: go-gntp-notify\r\n"+
			"Notification-Enabled: True\r\n"+
			"\r\n")
	if err == nil {
		res := string(b)
		if res[0:15] == "GNTP/1.0 -ERROR" {
			lines := strings.Split(res, "\r\n", 200)
			for n := range lines {
				if len(lines[n]) > 18 && lines[n][0:18] == "Error-Description:" {
					err = os.NewError(lines[n][19:])
					break
				}
			}
		}
	}
	return err
}

func (c *client) Notify(title string, text string, etc ...string) os.Error {
	icon := ""
	callback := ""
	if len(etc) > 0 {
		icon = etc[0]
	}
	if len(etc) > 1 {
		callback = etc[0]
	}
	b, err := c.send("NOTIFY",
		"Application-Name: "+c.appName+"\r\n"+
			"Notification-Name: go-gntp-notify\r\n"+
			"Notification-Title: "+title+"\r\n"+
			"Notification-Text: "+text+"\r\n"+
			"Notification-Icon: "+icon+"\r\n"+
			"Notification-Callback-Target: "+callback+"\r\n"+
			"\r\n")
	if err == nil {
		res := string(b)
		if res[0:15] == "GNTP/1.0 -ERROR" {
			lines := strings.Split(res, "\r\n", 200)
			for n := range lines {
				if len(lines[n]) > 18 && lines[n][0:18] == "Error-Description:" {
					err = os.NewError(lines[n][19:])
					break
				}
			}
		}
	}
	return err
}
