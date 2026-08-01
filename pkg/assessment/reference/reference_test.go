package reference

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestExtractDiscoversObjectReferencesAcrossRequestLocations(t *testing.T) {
	t.Parallel()

	query := make(url.Values)
	query.Add("IdCompany", "17")
	query.Add("entity_ids", "507f1f77bcf86cd799439011")
	query.Add("entity_ids", "550e8400-e29b-41d4-a716-446655440000")
	query.Add("identity", "42")
	query.Add("q", "shoes")

	refs, err := Extract(Input{
		PathTemplate: "/tenants/{tenantId}/orders/{order_id}",
		Path:         "/tenants/01ARZ3NDEKTSV4RRFFQ69G5FAV/orders/550e8400-e29b-41d4-a716-446655440000",
		Query:        query,
		Headers: http.Header{
			"X-Tenant-Id":   []string{"23"},
			"Authorization": []string{"Bearer definitely-not-a-real-token"},
		},
		Cookies: map[string]string{
			"account_id": "acct-west-7",
			"session_id": "session-value",
		},
		Parameters: []Parameter{
			{Name: "X-Tenant-Id", In: LocationHeader},
			{Name: "Authorization", In: LocationHeader},
			{Name: "account_id", In: LocationCookie},
			{Name: "session_id", In: LocationCookie},
		},
		Body: []byte(`{
			"person": {"personId": 91, "identity": 92},
			"requestedItems": [
				{"detector_ids": ["MTAx", "john-doe"]},
				{"serialNumber": "SN-2048"}
			],
			"owner": {"email": "owner@example.test"},
			"access_token": "not-an-object-reference"
		}`),
	})
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	want := map[string]struct {
		kind  Kind
		shape Shape
	}{
		"path:/tenants/{tenantId}":                   {KindULID, ShapeParentChild},
		"path:/tenants/{tenantId}/orders/{order_id}": {KindUUID, ShapeParentChild},
		"query:/IdCompany/0":                         {KindNumeric, ShapeScalar},
		"query:/entity_ids/0":                        {KindObjectID, ShapeBatch},
		"query:/entity_ids/1":                        {KindUUID, ShapeBatch},
		"header:/X-Tenant-Id/0":                      {KindNumeric, ShapeScalar},
		"cookie:/account_id":                         {KindSlug, ShapeScalar},
		"body:/person/personId":                      {KindNumeric, ShapeParentChild},
		"body:/requestedItems/0/detector_ids/0":      {KindBase64, ShapeBatch},
		"body:/requestedItems/0/detector_ids/1":      {KindSlug, ShapeBatch},
		"body:/requestedItems/1/serialNumber":        {KindNatural, ShapeParentChild},
		"body:/owner/email":                          {KindNatural, ShapeParentChild},
	}

	got := make(map[string]Reference, len(refs))
	for _, ref := range refs {
		got[string(ref.Location)+":"+ref.Pointer] = ref
	}
	for key, expected := range want {
		ref, ok := got[key]
		if !ok {
			t.Errorf("missing reference %s; got %#v", key, refs)
			continue
		}
		if ref.Kind != expected.kind || ref.Shape != expected.shape {
			t.Errorf("reference %s = kind %q shape %q, want kind %q shape %q", key, ref.Kind, ref.Shape, expected.kind, expected.shape)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("Extract() returned %d references, want %d: %#v", len(got), len(want), refs)
	}
}

func TestExtractNeverTreatsAuthenticationOrIdentityFieldsAsObjectReferences(t *testing.T) {
	t.Parallel()

	refs, err := Extract(Input{
		PathTemplate: "/search/{identity}",
		Path:         "/search/17",
		Query: url.Values{
			"identity":      []string{"17"},
			"sessionId":     []string{"18"},
			"access_token":  []string{"19"},
			"refresh_token": []string{"20"},
		},
		Headers: http.Header{
			"X-Api-Key": []string{"21"},
			"X-User-Id": []string{"22"},
		},
		Cookies: map[string]string{
			"session": "23",
			"user_id": "24",
		},
		Parameters: []Parameter{
			{Name: "X-Api-Key", In: LocationHeader},
			{Name: "X-User-Id", In: LocationHeader},
			{Name: "session", In: LocationCookie},
			{Name: "user_id", In: LocationCookie},
		},
		Body: []byte(`{"identity":25,"session_id":26,"csrfToken":27,"user_id":28}`),
	})
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	for _, ref := range refs {
		switch ref.Name {
		case "identity", "sessionId", "access_token", "refresh_token", "X-Api-Key", "session", "session_id", "csrfToken":
			t.Errorf("sensitive field %q classified as object reference: %#v", ref.Name, ref)
		}
	}
	if len(refs) != 3 {
		t.Fatalf("Extract() returned %#v, want only schema-declared X-User-Id and user_id cookie/body", refs)
	}
}

func TestExtractInfersReferencesFromConcretePathsWithoutTemplates(t *testing.T) {
	t.Parallel()

	refs, err := Extract(Input{Path: "/users/101/documents/550e8400-e29b-41d4-a716-446655440000"})
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("Extract() = %#v, want two inferred path references", refs)
	}
	if refs[0].Pointer != "/1" || refs[0].Name != "userId" || refs[0].Kind != KindNumeric || refs[0].Shape != ShapeParentChild {
		t.Errorf("first inferred reference = %#v", refs[0])
	}
	if refs[1].Pointer != "/3" || refs[1].Name != "documentId" || refs[1].Kind != KindUUID || refs[1].Shape != ShapeParentChild || refs[1].Parent != "/1" {
		t.Errorf("second inferred reference = %#v", refs[1])
	}
}

func TestClassifyRecognizesSupportedIdentifierFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		field     string
		value     string
		wantKind  Kind
		wantShape Shape
	}{
		{name: "numeric", field: "id", value: "101", wantKind: KindNumeric, wantShape: ShapeScalar},
		{name: "uuid", field: "userId", value: "550e8400-e29b-41d4-a716-446655440000", wantKind: KindUUID, wantShape: ShapeScalar},
		{name: "ulid", field: "orderId", value: "01ARZ3NDEKTSV4RRFFQ69G5FAV", wantKind: KindULID, wantShape: ShapeScalar},
		{name: "object id", field: "documentId", value: "507f1f77bcf86cd799439011", wantKind: KindObjectID, wantShape: ShapeScalar},
		{name: "base64 numeric", field: "userId", value: "MTAx", wantKind: KindBase64, wantShape: ShapeScalar},
		{name: "slug", field: "entity", value: "john-doe", wantKind: KindSlug, wantShape: ShapeScalar},
		{name: "natural key", field: "equipmentNumber", value: "SN2048", wantKind: KindNatural, wantShape: ShapeScalar},
		{name: "composite", field: "resourceKey", value: "tenant-7:order-42", wantKind: KindNatural, wantShape: ShapeComposite},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kind, shape, ok := Classify(tt.field, tt.value)
			if !ok {
				t.Fatal("Classify() ok = false, want true")
			}
			if kind != tt.wantKind || shape != tt.wantShape {
				t.Fatalf("Classify() = (%q, %q), want (%q, %q)", kind, shape, tt.wantKind, tt.wantShape)
			}
		})
	}
}

func TestExtractRejectsMalformedOrOversizedJSON(t *testing.T) {
	t.Parallel()

	for _, body := range [][]byte{[]byte(`{"id":`), []byte(`{"id":1} trailing`), make([]byte, MaximumBodyBytes+1)} {
		refs, err := Extract(Input{Body: body})
		if err == nil {
			t.Fatalf("Extract(%d bytes) = %#v, nil error; want rejection", len(body), refs)
		}
	}
}

func TestExtractFailsClosedAtTraversalAndReferenceLimits(t *testing.T) {
	t.Parallel()

	deepBody := strings.Repeat(`{"child":`, MaximumTraversalDepth+1) + `{"id":1}` + strings.Repeat(`}`, MaximumTraversalDepth+1)
	if _, err := Extract(Input{Body: []byte(deepBody)}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("deep Extract() error = %v, want ErrLimitExceeded", err)
	}

	values := make([]string, MaximumReferences+1)
	for index := range values {
		values[index] = "1"
	}
	if _, err := Extract(Input{Query: url.Values{"ids": values}}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("wide Extract() error = %v, want ErrLimitExceeded", err)
	}
}
