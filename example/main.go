package main

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/edomosystems/rqlite-adapter"
)

var enforcer *casbin.Enforcer

func main() {
	adapter := rqliteadapter.NewAdapter("http://10.10.40.23:4001")

	enforcer = casbin.NewEnforcer("model.conf", adapter, false)

	enforcer.LoadPolicy()

	enforcer.EnableAutoSave(true)

	fillDatabase()

	testPermissions()
}

func fillDatabase() {
	enforcer.AddRoleForUser("alice", "resident")
	enforcer.AddRoleForUser("bob", "facility")
	enforcer.AddRoleForUser("carol", "admin")

	enforcer.AddPermissionForUser("resident", "room", "read")
	enforcer.AddPermissionForUser("resident", "room", "write")
	enforcer.AddPermissionForUser("resident", "basement", "read")
	enforcer.AddPermissionForUser("resident", "basement", "write")

	enforcer.AddPermissionForUser("facility", "room", "read")
	enforcer.AddPermissionForUser("facility", "basement", "read")

	enforcer.AddPermissionForUser("admin", "basement", "write")
}

func testPermissions() {
	fmt.Println("> Alice is resident")
	fmt.Printf("%t: Alice can read room\n", enforcer.Enforce("alice", "room", "read"))
	fmt.Printf("%t: Alice can write room\n", enforcer.Enforce("alice", "room", "write"))
	fmt.Printf("%t: Alice can read basement\n", enforcer.Enforce("alice", "basement", "read"))
	fmt.Printf("%t: Alice can write basement\n", enforcer.Enforce("alice", "basement", "write"))

	fmt.Println("> Bob is facility")
	fmt.Printf("%t: Bob can read room\n", enforcer.Enforce("bob", "room", "read"))
	fmt.Printf("%t: Bob can write room\n", enforcer.Enforce("bob", "room", "write"))
	fmt.Printf("%t: Bob can read basement\n", enforcer.Enforce("bob", "basement", "read"))
	fmt.Printf("%t: Bob can write basement\n", enforcer.Enforce("bob", "basement", "write"))

	enforcer.AddRoleForUser("admin", "facility")

	fmt.Println("> Carol is admin - admin inherits from facility")
	fmt.Printf("%t: Carol can read room\n", enforcer.Enforce("carol", "room", "read"))
	fmt.Printf("%t: Carol can write room\n", enforcer.Enforce("carol", "room", "write"))
	fmt.Printf("%t: Carol can read basement\n", enforcer.Enforce("carol", "basement", "read"))
	fmt.Printf("%t: Carol can write basement\n", enforcer.Enforce("carol", "basement", "write"))

	enforcer.DeleteRoleForUser("carol", "admin")

	fmt.Println("> Carol is no longer admin")
	fmt.Printf("%t: Carol can read room\n", enforcer.Enforce("carol", "room", "read"))
	fmt.Printf("%t: Carol can write room\n", enforcer.Enforce("carol", "room", "write"))
	fmt.Printf("%t: Carol can read basement\n", enforcer.Enforce("carol", "basement", "read"))
	fmt.Printf("%t: Carol can write basement\n", enforcer.Enforce("carol", "basement", "write"))
}
