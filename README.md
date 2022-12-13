# `safeurl`

A Go library created to helps developers protect their applications from [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) attacks. It implements a `safeurl.Client` wrapper around Go's native `net/http.Client` and performs validation on the incoming request against the configured allow and block lists. It also implements mitigation for [DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding) attacks.

### Configuration options
The `safeurl.Client` can be configured through the `safeurl.Config` struct. It enables configuration of the following options:
```
AllowedPorts                    - list of ports the application is allowed to connect to
AllowedSchemes                  - list of schemas the application can use
AllowedHosts                    - list of hosts the application is allowed to communicate with
BlockedIPs                      - list of IP addresses the application is not allowed to connect to
AllowedIPs                      - list of IP addresses the application is allowed to connect to
AllowedCIDR                     - list of CIDR ranges the application is allowed to connect to
BlockedCIDR                     - list of CIDR ranges the application is not allowed to connect to

IsIPv6Enabled                   - specifies wether communication through IPv6 is enabled
AllowSendingCredentials         - specifies wether HTTP credentials should be sent

IsDebugLoggingEnabled          - enables debug logs
```
### How to use the safeurl.Client?
First, you need to include the `safeurl` module. To do that, simply add `github.com/doyensec/safeurl` to your project's `go.mod` file.

Sample:
```go
import (
    "fmt"
    "github.com/doyensec/safeurl"
)

func main() {
    config := safeurl.GetConfigBuilder().
        SetAllowedHosts("example.com").
        Build()

    client := safeurl.Client(config)

    resp, err := client.Get("https://example.com")
    if err != nil {
        fmt.Errorf("request return error: %v", err)
    }

    // read response body
}
```

### Running tests
To successfully run all the unit tests, you will need to run a local DNS and HTTP server. That can be done by executing the following command:

```bash
go run testing/servers.go
```

Once the servers are up and running, the unit test can be ran with:

```bash
go test -v
```

## Credits
This tool has been created by Viktor Chuchurski and Alessandro Cotto of [Doyensec LLC](https://www.doyensec.com) during research time. 

![alt text](https://doyensec.com/images/logo.svg "Doyensec Logo")