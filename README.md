# eveauth

A Go library for authenticating characters with the EVE Online SSO service on desktops.

![GitHub Release](https://img.shields.io/github/v/release/ErikKalkoken/eveauth)
[![CI/CD](https://github.com/ErikKalkoken/eveauth/actions/workflows/go.yml/badge.svg)](https://github.com/ErikKalkoken/eveauth/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/ErikKalkoken/eveauth/graph/badge.svg?token=lpXxAzgLva)](https://codecov.io/gh/ErikKalkoken/eveauth)
![GitHub License](https://img.shields.io/github/license/ErikKalkoken/eveauth)
[![Go Reference](https://pkg.go.dev/badge/github.com/ErikKalkoken/eveauth.svg)](https://pkg.go.dev/github.com/ErikKalkoken/eveauth)

## Description

eveauth is a Go library that provides the ability to authenticate characters with the Eve Online Single Sign-On (SSO) service.

It implements OAuth 2.0 with the PKCS authorization flow and is designed for desktop applications.

## Installation

You can add eveauth to your Go module with the following command:

```sh
go get github.com/ErikKalkoken/eveauth
```

## Usage

This section describes how to use the eveauth library to authenticate EVE Online characters with your desktop app.

### Creating the SSO application

First you need to create an SSO application on the [developers website](https://developers.eveonline.com/applications).

Chose name and enabled scopes depending your requirements.

Your callback URL should look something like this: `http://localhost:8000/callback`. The port (i.e. `8000`) and callback path (i.e. `callback`) can be configured when creating the eveauth client.

The client ID generated for your SSO app will be needed later for configuring the eveauth client.

### Using eveauth in a Go program

The following program shows how to use eveauth. It will open the system's default web browser and after completing the OAuth flow for a character will return a token with the `pubicData` scope.

```go
package main

import (
	"context"
	"fmt"

	"github.com/ErikKalkoken/eveauth"
)


func main() {
	client, err := eveauth.NewClient(eveauth.Config{
		ClientID: "YOUR-SSO-CLIENT-ID",
		Port:     8000,
	})
	if err != nil {
		panic(err)
	}
	tok, err := client.Authenticate(context.Background(), []string{"publicData"})
	if err != nil {
		panic(err)
	}
	fmt.Println(tok)
}
```
