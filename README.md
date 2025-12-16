# eveauth

A Go library for authorizing desktop applications with the EVE Online SSO service.

![GitHub Release](https://img.shields.io/github/v/release/ErikKalkoken/eveauth)
[![CI/CD](https://github.com/ErikKalkoken/eveauth/actions/workflows/go.yml/badge.svg)](https://github.com/ErikKalkoken/eveauth/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/ErikKalkoken/eveauth/graph/badge.svg?token=lpXxAzgLva)](https://codecov.io/gh/ErikKalkoken/eveauth)
![GitHub License](https://img.shields.io/github/license/ErikKalkoken/eveauth)
[![Go Reference](https://pkg.go.dev/badge/github.com/ErikKalkoken/eveauth.svg)](https://pkg.go.dev/github.com/ErikKalkoken/eveauth)

## Description

**eveauth** is a Go library for authorizing desktop applications with the EVE Online [Single Sign-On](https://developers.eveonline.com/docs/services/sso/) (SSO) service.

It's key features are:

- Authorize desktop apps with the EVE Online SSO service
- Renew obtained token
- Cross-platform support (e.g. Windows, macOS, Linux)
- Logging support
- Configurable client

> [!TIP]
> Platform compatibility is mainly determined by the feature for opening a URL in the browser. The default configuration uses [github.com/toqueteos/webbrowser](https://github.com/toqueteos/webbrowser), which provides this feature for many popular platforms including Windows, macOS and Linux. Other platforms can be supported by providing a platform specific implementation of this feature. For example the application [EVE Buddy](https://github.com/ErikKalkoken/evebuddy) is using **eveauth** on Android with support from the [Fyne GUI toolkit](https://github.com/fyne-io/fyne).

## Installation

You can add **eveauth** to your Go module with the following command:

```sh
go get github.com/ErikKalkoken/eveauth
```

## Usage

This section describes how to use the **eveauth** library.

### Creating the SSO application

First you need to create an SSO application on the [developers website](https://developers.eveonline.com/applications).

Chose name and enabled scopes depending your requirements. Please make sure it as at least the `pubicData` scope for this example below to work.

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
	tok, err := client.Authorize(context.Background(), []string{"publicData"})
	if err != nil {
		panic(err)
	}
	fmt.Println(tok)
}
```

## Projects using eveauth

The following projects are using **eveauth**:

- [elt](https://github.com/ErikKalkoken/elt): A command line tool for looking up Eve Online objects.
- [EVE Buddy](https://github.com/ErikKalkoken/evebuddy): A companion app for Eve Online players available on Windows, macOS, Linux and Android.
