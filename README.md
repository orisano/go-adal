# go-ADAL
<a href="https://travis-ci.com/orisano/go-adal"><img src="https://travis-ci.com/orisano/go-adal.svg?branch=master" alt="Build Status"></img></a>
<a href="https://codeclimate.com/github/orisano/go-adal"><img src="https://codeclimate.com/github/orisano/go-adal/badges/gpa.svg" alt="Code Climate"></img></a>
<a href="https://codeclimate.com/github/orisano/go-adal/coverage"><img src="https://codeclimate.com/github/orisano/go-adal/badges/coverage.svg" /></a>

unofficial Active Directory Authentication Library for go.

## Installation
```
go get github.com/orisano/go-adal
```

## How to Use
```go
package main

import (
	"context"
	"io"
	"log"
	"os"
	
	"github.com/orisano/go-adal"
)

const (
	tenant = "common"
	resource = "resource.example"
	clientID = "xxxxxxxxxxxxxxxxx"
	clientSecret = "xxxxxxxxxxxxxxxxx"
)

func main() {
	ac, err := adal.NewAuthenticationContext(tenant)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	client, err := ac.Client(ctx, resource, clientID, clientSecret)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Get("http://api.example/v1/resource")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	
	io.Copy(os.Stdout, resp.Body)
}
```

## Author
Nao Yonashiro (@orisano)

## License
MIT
