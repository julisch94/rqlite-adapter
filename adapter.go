// Copyright 2017 EDOMO Systems GmbH. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rqliteadapter

import (
	"fmt"
	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	"github.com/raindog308/gorqlite"
	"runtime"
)

var tableName = "rules"

type CasbinRule struct {
	PType, V0, V1, V2, V3, V4, V5 string
}

// Adapter represents the RQLite adapter for policy storage.
type Adapter struct {
	url  string
	conn *gorqlite.Connection
}

func finalizer(a *Adapter) {
	a.conn.Close()
}

// NewAdapter is the constructor for Adapter. It requires the url of the RQLite connection.
// An example url could be http://10.10.40.23:4001. Wherever your RQLite is being served.
// Make sure you use the HTTP address.
func NewAdapter(url string) *Adapter {
	a := &Adapter{}
	a.url = url

	a.open()

	runtime.SetFinalizer(a, finalizer)

	return a
}

func (a *Adapter) open() {
	conn, err := gorqlite.Open(a.url)
	if err != nil {
		panic(err)
	}

	a.conn = &conn

	a.createTable()
}

func (a *Adapter) close() {
	a.conn.Close()
}

func (a *Adapter) createTable() {
	stmt := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (p_type TEXT NULL, v0 TEXT NULL, v1 TEXT NULL, v2 TEXT NULL, v3 TEXT NULL, v4 TEXT NULL, v5 TEXT NULL, PRIMARY KEY(p_type, v0, v1, v2, v3, v4, v5))", tableName)
	a.conn.WriteOne(stmt)
}

func (a *Adapter) dropTable() {
	stmt := fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName)
	a.conn.WriteOne(stmt)
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	lineText := line.PType
	if line.V0 != "" {
		lineText += ", " + line.V0
	}
	if line.V1 != "" {
		lineText += ", " + line.V1
	}
	if line.V2 != "" {
		lineText += ", " + line.V2
	}
	if line.V3 != "" {
		lineText += ", " + line.V3
	}
	if line.V4 != "" {
		lineText += ", " + line.V4
	}
	if line.V5 != "" {
		lineText += ", " + line.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

// LoadPolicy loads policy from RQLite database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var err error
	var result gorqlite.QueryResult

	result, err = a.conn.QueryOne(fmt.Sprintf("SELECT * FROM %s", tableName))
	if err != nil {
		return err
	}

	for result.Next() {
		var line CasbinRule
		err = result.Scan(&line)
		loadPolicyLine(line, model)
	}

	return nil
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to RQLite database.
func (a *Adapter) SavePolicy(model model.Model) error {
	a.dropTable()
	a.createTable()

	var lines []CasbinRule

	// Save policy lines
	for ptype, assertion := range model["p"] {
		for _, rule := range assertion.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	// Save group lines
	for ptype, assertion := range model["g"] {
		for _, rule := range assertion.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	err := a.writeLines(lines)
	return err
}

func (a *Adapter) writeLines(lines []CasbinRule) error {
	for _, l := range lines {
		err := a.writeLine(l)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) writeLine(line CasbinRule) error {
	columns := "p_type, v0, v1, v2, v3, v4, v5"

	values := "'" + line.PType + "'"
	values += ", '" + line.V0 + "'"
	values += ", '" + line.V1 + "'"
	values += ", '" + line.V2 + "'"
	values += ", '" + line.V3 + "'"
	values += ", '" + line.V4 + "'"
	values += ", '" + line.V5 + "'"

	// ignore and don't insert if entry already exists
	stmt := fmt.Sprintf("INSERT OR IGNORE INTO %s (%s) VALUES (%s)", tableName, columns, values)
	_, err := a.conn.WriteOne(stmt)
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	err := a.writeLine(line)
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	condition := "p_type = '" + ptype + "'"

	if len(rule) > 0 {
		condition += " AND v0 = '" + rule[0] + "'"
	}
	if len(rule) > 1 {
		condition += " AND v1 = '" + rule[1] + "'"
	}
	if len(rule) > 2 {
		condition += " AND v2 = '" + rule[2] + "'"
	}
	if len(rule) > 3 {
		condition += " AND v3 = '" + rule[3] + "'"
	}
	if len(rule) > 4 {
		condition += " AND v4 = '" + rule[4] + "'"
	}
	if len(rule) > 5 {
		condition += " AND v5 = '" + rule[5] + "'"
	}

	stmt := fmt.Sprintf("DELETE FROM %s WHERE %s", tableName, condition)
	_, err := a.conn.WriteOne(stmt)
	return err
}

func (a *Adapter) removeLine(sec string, line CasbinRule) error {
	ptype := line.PType
	var rules []string
	rules = append(rules, line.V0)
	rules = append(rules, line.V1)
	rules = append(rules, line.V2)
	rules = append(rules, line.V3)
	rules = append(rules, line.V4)
	rules = append(rules, line.V5)
	err := a.RemovePolicy(sec, ptype, rules)
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := CasbinRule{}

	line.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex + len(fieldValues) {
		line.V0 = fieldValues[0 - fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex + len(fieldValues) {
		line.V1 = fieldValues[1 - fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex + len(fieldValues) {
		line.V2 = fieldValues[2 - fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex + len(fieldValues) {
		line.V3 = fieldValues[3 - fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex + len(fieldValues) {
		line.V4 = fieldValues[4 - fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex + len(fieldValues) {
		line.V5 = fieldValues[5 - fieldIndex]
	}

	err := a.removeLine(sec, line)
	return err
}