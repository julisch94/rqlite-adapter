RQLite Adapter
====

[![GoDoc](https://godoc.org/github.com/edomosystems/rqlite-adapter?status.svg)](https://godoc.org/github.com/edomosystems/rqlite-adapter)

This adapter is the [RQLite](https://github.com/rqlite/rqlite) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policies from RQLite databases or save policies to it which will then be distributed over the RQLite cluster.

## Installation

    go get github.com/edomosystems/rqlite-adapter


## Simple Example

```go
package main

import (
  "fmt"
  "github.com/casbin/casbin"
  "github.com/edomosystems/rqlite-adapter"
)

func main() {
  /* Specify the http api url your
  * rqlite node is listening on */
  adapter := rqliteadapter.NewAdapter("http://10.10.40.23:4001")

  enforcer := casbin.NewEnforcer("model.conf", adapter, false)

  enforcer.LoadPolicy()
  enforcer.EnableAutoSave(true)

  enforcer.AddRoleForUser("alice", "admin")
  enforcer.AddRoleForUser("bob", "guest")

  enforcer.AddPermissionForUser("admin", "file", "read")
  enforcer.AddPermissionForUser("admin", "file", "write")
  enforcer.AddPermissionForUser("guest", "file", "read")

  enforcer.Enforce("alice", "file", "read")    // -> True
  enforcer.Enforce("alice", "file", "write")   // -> True
  enforcer.Enforce("bob", "file", "read")      // -> True
  enforcer.Enforce("bob", "file", "write")     // -> False

  /* Simple role hirearchie */
  enforcer.AddRoleForUser("chalie", "interim")
  enforcer.AddRoleForUser("interim", "guest")  // interim inherits from guest

  enforcer.Enforce("charlie", "file", "read")  // -> True
  enforcer.Enforce("charlie", "file", "write") // -> False
}
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
