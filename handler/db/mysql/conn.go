package mysql

import "database/sql"

var db *sql.DB

func init() {
	db, _ = sql.Open("mysql", "root")
}
