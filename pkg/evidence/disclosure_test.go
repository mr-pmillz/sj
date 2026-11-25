package evidence

import (
	"slices"
	"testing"
)

func TestDisclosureTypesAndTiers(t *testing.T) {
	if DisclosureTypes(nil) != nil {
		t.Fatal("an empty body has no disclosure")
	}
	body := []byte(`{"detail":"(pyodbc.IntegrityError) [SQL: INSERT INTO dbo.users] table dbo.app.users column email"}`)
	types := DisclosureTypes(body)
	for _, want := range []string{"database_driver", "sql_statement", "database_table", "database_column"} {
		if !slices.Contains(types, want) {
			t.Errorf("types %v lack %s", types, want)
		}
	}
	medium, low := DisclosureTiers(types, 500)
	// Supporting types follow the medium ones they are promoted next to.
	if !slices.Equal(medium, []string{"database_driver", "sql_statement", "database_column", "database_table"}) || len(low) != 0 {
		t.Fatalf("medium %v, low %v", medium, low)
	}
	// A table name alone is supporting evidence. It counts on an error response only.
	if medium, _ := DisclosureTiers([]string{"database_table"}, 200); len(medium) != 0 {
		t.Fatalf("a table name on a 200 response was promoted: %v", medium)
	}
	if medium, _ := DisclosureTiers([]string{" database_table ", "", "database_table"}, 404); !slices.Equal(medium, []string{"database_table"}) {
		t.Fatalf("names are trimmed and deduplicated: %v", medium)
	}
	if medium, low := DisclosureTiers(DisclosureTypes([]byte("json: cannot unmarshal string into Go value")), 400); len(medium) != 0 || !slices.Equal(low, []string{"runtime_diagnostic"}) {
		t.Fatalf("runtime diagnostic tier: %v %v", medium, low)
	}
}
