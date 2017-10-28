# go-gntp

GNTP client for Go

## Usage

```
client := gntp.NewClient()
client.AppName = "my-app"
client.Server = "localhost:23053"
client.Password = "foobar"
client.HashAlgorithm = "SHA256"
client.EncryptAlgorithm = "AES"
n := []gntp.Notification{Event: "MyEvent", DisplayName: "My Event Name", Enabled: true}}
client.Register(n)
m := gntp.Message{Event: "MyEvent", Title: "my-title", Text: "my-text"}
client.Send(&m)
```

## Installation

```
go get github.com/mattn/go-gntp
```

## License

MIT

## Author

Yasuhiro Matsumoto (a.k.a. mattn)
