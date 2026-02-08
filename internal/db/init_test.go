
package db

// import "testing"
//
// func TestInit_CreatesSchema(t *testing.T) {
// 	db := newTestDB(t)
// 	defer db.Close()
//
// 	// tables exist
// 	for _, table := range []string{"entries", "folders", "meta"} {
// 		var name string
// 		err := db.QueryRow(
// 			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`,
// 			table,
// 		).Scan(&name)
//
// 		if err != nil {
// 			t.Fatalf("table %s not created: %v", table, err)
// 		}
// 	}
// }
//
// func TestInit_InsertsMetaDefaults(t *testing.T) {
// 	db := newTestDB(t)
// 	defer db.Close()
//
// 	v, err := GetMeta(db, "schema_version")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	mustEqual(t, v, "1")
//
// 	v, err = GetMeta(db, "last_migration")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	mustEqual(t, v, "0")
// }
