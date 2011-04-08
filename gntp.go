package gntp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/aes"
	"crypto/des"
	"crypto/cipher"
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
	icon             string
}

func makeRand(size int) []byte {
	r := make([]byte, size)
	for n := 0; n < len(r); n++ {
		r[n] = uint8(rand.Int() % 256)
	}
	return r
}

func makeSalt(size int) []byte {
	s := make([]byte, size)
	cc := "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for n := 0; n < len(s); n++ {
		s[n] = uint8(cc[rand.Int()%len(cc)])
	}
	return s
}

func (c *client) send(method string, stm string) (ret []byte, err os.Error) {
	conn, err := net.Dial("tcp", c.server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if len(c.password) > 0 {
		salt := makeSalt(8)
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
		key := ha.Sum()
		hashHdr := fmt.Sprintf("%s:%X.%X", c.hashAlgorithm, key, salt)

		ha.Reset()
		ha.Write([]byte(c.password))
		ha.Write(salt)
		hk := ha.Sum()

		encHdr := c.encryptAlgorithm
		in := ([]byte)(stm)
		var out []byte
		switch c.encryptAlgorithm {
		case "AES":
			if len(hk) < 24 {
				return nil, os.NewError("key length is too short. maybe hash algorithm is wrong for this encrypt algorithm")
			}
			ci, err := aes.NewCipher(hk[0:24])
			if err != nil {
				return nil, err
			}
			iv := makeRand(16)
			enc := cipher.NewCBCEncrypter(ci, iv)
			cin := make([]byte, int(len(in)/aes.BlockSize)*aes.BlockSize+aes.BlockSize)
			copy(cin[0:], in[0:])
			for nn := len(in); nn < len(cin); nn++ {
				cin[nn] = byte(len(cin) - len(in))
			}
			out = make([]byte, len(cin))
			enc.CryptBlocks(out, cin)
			encHdr += fmt.Sprintf(":%X", iv)
		case "DES":
			if len(hk) < 8 {
				return nil, os.NewError("key length is too short. maybe hash algorithm is wrong for this encrypt algorithm")
			}
			ci, err := des.NewCipher(hk[0:8])
			if err != nil {
				return nil, err
			}
			iv := makeRand(8)
			enc := cipher.NewCBCEncrypter(ci, iv)
			cin := make([]byte, int(len(in)/des.BlockSize)*des.BlockSize+des.BlockSize)
			copy(cin[0:], in[0:])
			for nn := len(in); nn < len(cin); nn++ {
				cin[nn] = byte(len(cin)-len(in))
			}
			out = make([]byte, len(cin))
			enc.CryptBlocks(out, cin)
			encHdr += fmt.Sprintf(":%X", iv)
		case "3DES":
			if len(hk) < 24 {
				return nil, os.NewError("key length is too short. maybe hash algorithm is wrong for this encrypt algorithm")
			}
			ci, err := des.NewTripleDESCipher(hk[0:24])
			if err != nil {
				return nil, err
			}
			iv := makeRand(8)
			enc := cipher.NewCBCEncrypter(ci, iv)
			cin := make([]byte, int(len(in)/des.BlockSize)*des.BlockSize+des.BlockSize)
			copy(cin[0:], in[0:])
			for nn := len(in); nn < len(cin); nn++ {
				cin[nn] = byte(len(cin)-len(in))
			}
			out = make([]byte, len(cin))
			enc.CryptBlocks(out, cin)
			encHdr += fmt.Sprintf(":%X", iv)
		case "NONE":
			out = in
		default:
			return nil, os.NewError("unknown encrypt algorithm")
		}

		conn.Write([]byte("GNTP/1.0 " + method + " " + encHdr + " " + hashHdr + "\r\n"))
		conn.Write(out)
		conn.Write([]byte("\r\n\r\n"))
	} else {
		conn.Write([]byte(
			"GNTP/1.0 " + method + " NONE\r\n" + stm + "\r\n"))
	}
	return ioutil.ReadAll(conn)
}

func NewClient() *client {
	return &client{"localhost:23053", "", "go-gntp-send", "MD5", "NONE", ""}
}

func NewClientWithPassword(password string) *client {
	return &client{"localhost:23053", password, "go-gntp-send", "MD5", "NONE", ""}
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

func (c *client) SetIcon(icon string) {
	c.icon = icon
}

type Notification struct {
	Event       string
	DisplayName string
	Enabled     bool
}

func (c *client) Register(n []Notification) os.Error {
	s := fmt.Sprintf(
		"Application-Name: %s\r\n"+
			"Notifications-Count: %d\r\n\r\n",c.appName, len(n))
	for _, i := range n {
		s += "Notification-Name: " + i.Event + "\r\n" +
			"Notification-Display-Name: " + i.DisplayName + "\r\n" +
			"Notification-Enabled: True\r\n\r\n"
	}
	b, err := c.send("REGISTER", s)
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

func (c *client) Notify(event string, title string, text string, etc ...string) os.Error {
	icon := c.icon
	callback := ""
	if len(etc) > 0 {
		icon = etc[0]
	}
	if len(etc) > 1 {
		callback = etc[1]
	}
	b, err := c.send("NOTIFY",
		"Application-Name: "+c.appName+"\r\n"+
			"Notification-Name: "+event+"\r\n"+
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
