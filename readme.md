This repository is a traefik plugin, which acts as a middleware to block unnecessary traffic.

# About

[Traefik](https://traefik.io) plugins are developed using the [Go language](https://golang.org).

A [Traefik](https://traefik.io) middleware plugin is just a [Go package](https://golang.org/ref/spec#Packages) that provides an `http.Handler` to perform specific processing of requests and responses.

## Usage

For a plugin to be active for a given Traefik instance, it must be declared in the static configuration.

Plugins are parsed and loaded exclusively during startup, which allows Traefik to check the integrity of the code and catch errors early on.
If an error occurs during loading, the plugin is disabled.

For security reasons, it is not possible to start a new plugin or modify an existing one while Traefik is running.

Once loaded, middleware plugins behave exactly like statically compiled middlewares.
Their instantiation and behavior are driven by the dynamic configuration.

This plugin blocks unwanted requests by returning 403 response with the error code

### Configuration

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

The following declaration (given here in YAML) defines a plugin:

```yaml
# Static configuration

traefik_plugins:
  white-elephant:
    repo: https://github.com/golubev-ml/white-elephant
    version: v1.0.0
```

Here is an example of dynamic configuration, where the interesting part is the `http.middlewares` section:

```yaml
# Dynamic configuration

http:
  ...  
  middlewares:
    white-elephant:
      plugin:
        white-elephant:
          white_list:
            - "whitelist_regexp_1"
            - "whitelist_regexp_2"          
          partner_ids:
            - "b157961d5da94f6b9e9fb34b57a9346b"
            - "d2c63a605ae27c13e43e26fe2c97a36c"
          key_lifetime: 3600
          secret_key: "thisis32bitlongpassphraseimusing"

```

Here
- `white_list` - list of regular expressions for which this check is disabled 
- `partner_ids` - list of strings to compare unencrypted data against
- `key_lifetime` - duration of token expiration
- `secret_key` - used for token encryption

## Defining a Plugin

A plugin package defines the following exported Go objects:

- A type `type Config struct { ... }`. The struct fields are arbitrary.
- A function `func CreateConfig() *Config`.
- A function `func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error)`.

```go
// Package example a example plugin.
package example

import (
	"context"
	"net/http"
)

// Config the plugin configuration.
type Config struct {
	// ...
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		// ...
	}
}

// Example a plugin.
type Example struct {
	next     http.Handler
	name     string
	// ...
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// ...
	return &Example{
		// ...
	}, nil
}

func (e *Example) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ...
	e.next.ServeHTTP(rw, req)
}
```

## Logs

Logs are sent using `os.Stdout.WriteString("...")` or `os.Stderr.WriteString("...")`.

