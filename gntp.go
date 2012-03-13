package gntp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"math/rand"
	"net"
	"strings"
)

type Client struct {
	Server           string
	Password         string
	AppName          string
	HashAlgorithm    string
	EncryptAlgorithm string
}

type Notification struct {
	Event       string
	DisplayName string
	Enabled     bool
}

type Message struct {
	Event       string
	Title       string
	Text        string
	Icon        string
	Callback    string
	DisplayName string
}

func makeRand(size int) []byte {
	r := make([]byte, size)
	for n := 0; n < len(r); n++ {
		r[n] = uint8(rand.Int() % 256)
	}
	return r
}

func sanitize(str string) string {
	return strings.Replace(str, "\r\n", "\n", -1)
}

func makeSalt(size int) []byte {
	s := make([]byte, size)
	cc := "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for n := 0; n < len(s); n++ {
		s[n] = uint8(cc[rand.Int()%len(cc)])
	}
	return s
}

func (c *Client) send(method string, stm string) (ret []byte, err error) {
	conn, err := net.Dial("tcp", c.Server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if len(c.Password) > 0 {
		salt := makeSalt(8)
		var ha hash.Hash
		switch c.HashAlgorithm {
		case "MD5":
			ha = md5.New()
		case "SHA1":
			ha = sha1.New()
		case "SHA256":
			ha = sha256.New()
		default:
			return nil, errors.New("unknown hash algorithm")
		}
		ha.Write([]byte(c.Password))
		ha.Write(salt)
		hv := ha.Sum(nil)
		ha.Reset()
		ha.Write(hv)
		key := ha.Sum(nil)
		hashHdr := fmt.Sprintf("%s:%X.%X", c.HashAlgorithm, key, salt)

		ha.Reset()
		ha.Write([]byte(c.Password))
		ha.Write(salt)
		hk := ha.Sum(nil)

		encHdr := c.EncryptAlgorithm
		in := ([]byte)(stm)
		var out []byte
		switch c.EncryptAlgorithm {
		case "AES":
			if len(hk) < 24 {
				return nil, errors.New("key length is too short. maybe hash algorithm is wrong for this encrypt algorithm")
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
				return nil, errors.New("key length is too short. maybe hash algorithm is wrong for this encrypt algorithm")
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
				cin[nn] = byte(len(cin) - len(in))
			}
			out = make([]byte, len(cin))
			enc.CryptBlocks(out, cin)
			encHdr += fmt.Sprintf(":%X", iv)
		case "3DES":
			if len(hk) < 24 {
				return nil, errors.New("key length is too short. maybe hash algorithm is wrong for this encrypt algorithm")
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
				cin[nn] = byte(len(cin) - len(in))
			}
			out = make([]byte, len(cin))
			enc.CryptBlocks(out, cin)
			encHdr += fmt.Sprintf(":%X", iv)
		case "NONE":
			out = in
		default:
			return nil, errors.New("unknown encrypt algorithm")
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

func NewClient() *Client {
	return &Client{"localhost:23053", "", "gntp-send", "MD5", "NONE"}
}

func (c *Client) Register(n []Notification) error {
	s := fmt.Sprintf(
		"Application-Name: %s\r\n"+
			"Notifications-Count: %d\r\n\r\n", sanitize(c.AppName), len(n))
	for _, i := range n {
		s += "Notification-Name: " + sanitize(i.Event) + "\r\n" +
			"Notification-Display-Name: " + sanitize(i.DisplayName) + "\r\n" +
			"Notification-Enabled: True\r\n\r\n"
	}
	b, err := c.send("REGISTER", s)
	if err == nil {
		res := string(b)
		if res[0:15] == "GNTP/1.0 -ERROR" {
			lines := strings.Split(res, "\r\n")
			for n := range lines {
				if len(lines[n]) > 18 && lines[n][0:18] == "Error-Description:" {
					err = errors.New(lines[n][19:])
					break
				}
			}
		}
	}
	return err
}

func (c *Client) Notify(m *Message) error {
	if b, err := ioutil.ReadFile(m.Icon); err == nil {
		ha := md5.New()
		ha.Write(b)
		m.Icon = "x-growl-resource://" + string(ha.Sum(nil))
	}
	b, err := c.send("NOTIFY",
		"Application-Name: "+sanitize(c.AppName)+"\r\n"+
			"Notification-Name: "+sanitize(m.Event)+"\r\n"+
			"Notification-Title: "+sanitize(m.Title)+"\r\n"+
			"Notification-Text: "+sanitize(m.Text)+"\r\n"+
			"Notification-Icon: "+sanitize(m.Icon)+"\r\n"+
			"Notification-Callback-Target: "+sanitize(m.Callback)+"\r\n"+
			"Notification-Display-Name: "+sanitize(m.DisplayName)+"\r\n"+
			"\r\n")
	if err == nil {
		res := string(b)
		if res[0:15] == "GNTP/1.0 -ERROR" {
			lines := strings.Split(res, "\r\n")
			for n := range lines {
				if len(lines[n]) > 18 && lines[n][0:18] == "Error-Description:" {
					err = errors.New(lines[n][19:])
					break
				}
			}
		}
	}
	return err
}
