package gntp

import (
	"bytes"
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
	for i := range r {
		r[i] = byte(rand.Int() % 256)
	}
	return r
}

func sanitize(str string) string {
	return strings.Replace(str, "\r\n", "\n", -1)
}

func makeSalt(size int) []byte {
	s := make([]byte, size)
	cc := "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for i := range s {
		s[i] = byte(cc[rand.Int()%len(cc)])
	}
	return s
}

func (c *Client) send(method string, stm []byte) (ret []byte, err error) {
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
		in := stm
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

		conn.Write([]byte(fmt.Sprintf("GNTP/1.0 %s %s %s\r\n", method, encHdr, hashHdr)))
		conn.Write(out)
		conn.Write([]byte("\r\n\r\n"))
	} else {
		conn.Write([]byte(fmt.Sprintf("GNTP/1.0 %s NONE\r\n%s\r\n", method, string(stm))))
	}
	return ioutil.ReadAll(conn)
}

func NewClient() *Client {
	return &Client{"localhost:23053", "", "gntp-send", "MD5", "NONE"}
}

func (c *Client) Register(n []Notification) error {
	data := new(bytes.Buffer)
	fmt.Fprintf(data, "Application-Name: %s\r\n", sanitize(c.AppName))
	fmt.Fprintf(data, "Notifications-Count: %d\r\n\r\n", len(n))
	for _, i := range n {
		var enabled string
		if i.Enabled {
			enabled = "True"
		} else {
			enabled = "False"
		}
		fmt.Fprintf(data, "Notification-Name: %s\r\n", sanitize(i.Event))
		fmt.Fprintf(data, "Notification-Display-Name: %s\r\n", sanitize(i.DisplayName))
		fmt.Fprintf(data, "Notification-Enabled: %s\r\n\r\n", enabled)
	}
	b, err := c.send("REGISTER", data.Bytes())
	if err == nil {
		res := string(b)
		if strings.HasPrefix(res, "GNTP/1.0 -ERROR") {
			lines := strings.Split(res, "\r\n")
			for _, l := range lines {
				if strings.HasPrefix(l, "Error-Description:") {
					err = errors.New(l[19:])
					break
				}
			}
		}
	}
	return err
}

func (c *Client) Notify(m *Message) error {
	identify, err := ioutil.ReadFile(m.Icon)
	if err == nil {
		ha := md5.New()
		ha.Write(identify)
		m.Icon = fmt.Sprintf("x-growl-resource://%X", ha.Sum(nil))
	}
	data := new(bytes.Buffer)
	fmt.Fprintf(data, "Application-Name: %s\r\n", sanitize(c.AppName))
	fmt.Fprintf(data, "Notification-Name: %s\r\n", sanitize(m.Event))
	fmt.Fprintf(data, "Notification-Title: %s\r\n", sanitize(m.Title))
	fmt.Fprintf(data, "Notification-Text: %s\r\n", sanitize(m.Text))
	fmt.Fprintf(data, "Notification-Icon: %s\r\n", sanitize(m.Icon))
	fmt.Fprintf(data, "Notification-Callback-Target: %s\r\n", sanitize(m.Callback))
	fmt.Fprintf(data, "Notification-Display-Name: %s\r\n\r\n", sanitize(m.DisplayName))
	if len(identify) > 0 {
		fmt.Fprintf(data, "Identifier: %s\r\n", m.Icon[19:])
		fmt.Fprintf(data, "Length: %d\r\n\r\n", len(identify))
		data.Write(identify)
		data.Write([]byte("\r\n\r\n"))
	}
	b, err := c.send("NOTIFY", data.Bytes())
	if err == nil {
		res := string(b)
		if strings.HasPrefix(res, "GNTP/1.0 -ERROR") {
			lines := strings.Split(res, "\r\n")
			for _, l := range lines {
				if strings.HasPrefix(l, "Error-Description:") {
					err = errors.New(l[19:])
					break
				}
			}
		}
	}
	return err
}
