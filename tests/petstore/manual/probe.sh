#!/usr/bin/env bash
# Manual ground-truth probe of the public Petstore sandbox. Independent of sj.
B=https://petstore.swagger.io/v2
R=$(( 7700000000 + RANDOM * 31 + RANDOM ))
U="sjkey$RANDOM$RANDOM"
PW="canary-$RANDOM$RANDOM"
p() { local label=$1; shift; sleep 0.35; local code; code=$(curl -sS -m 20 -o body.tmp -D hdr.tmp -w '%{http_code}' "$@"); printf '%-46s %s  %s\n' "$label" "$code" "$(head -c 170 body.tmp | tr '\n' ' ')"; }
echo "pet id $R user $U"
PET="{\"id\":$R,\"name\":\"sj-probe\",\"photoUrls\":[],\"status\":\"available\"}"
echo "== declared security, no credential =="
p "addPet anon"            -X POST -H 'Content-Type: application/json' -d "$PET" $B/pet
p "getPetById anon"        $B/pet/$R
p "getPetById anon (2)"    $B/pet/$R
p "getPetById anon (3)"    $B/pet/$R
p "updatePet anon"         -X PUT -H 'Content-Type: application/json' -d "${PET/sj-probe/sj-probe2}" $B/pet
p "findByStatus anon"      "$B/pet/findByStatus?status=pending"
p "findByTags anon"        "$B/pet/findByTags?tags=sj-none"
p "updatePetWithForm anon" -X POST -d 'name=sj-form&status=pending' $B/pet/$R
p "uploadFile anon"        -X POST -F 'additionalMetadata=sj' -F 'file=@probe.sh;filename=sj.txt;type=text/plain' $B/pet/$R/uploadImage
p "getInventory anon"      $B/store/inventory
echo "== declared security, invalid credential =="
p "getPetById bad key"     -H 'api_key: sj-invalid-key' $B/pet/$R
p "getInventory bad key"   -H 'api_key: sj-invalid-key' $B/store/inventory
p "updatePet bad bearer"   -X PUT -H 'Authorization: Bearer sj-invalid-token' -H 'Content-Type: application/json' -d "$PET" $B/pet
p "findByStatus bad bearer" -H 'Authorization: Bearer sj-invalid-token' "$B/pet/findByStatus?status=pending"
p "deletePet bad bearer"   -X DELETE -H 'Authorization: Bearer sj-invalid-token' $B/pet/$R
p "getPetById after delete" $B/pet/$R
p "getPetById after delete (2)" $B/pet/$R
p "deletePet again anon"   -X DELETE $B/pet/$R
echo "== user operations (no declared security; docs say logged-in user only) =="
p "createUser anon"        -X POST -H 'Content-Type: application/json' -d "{\"id\":$R,\"username\":\"$U\",\"password\":\"$PW\",\"email\":\"sj@example.com\"}" $B/user
p "getUserByName anon"     $B/user/$U
grep -c "$PW" body.tmp | sed 's/^/   password canary occurrences in body: /'
p "login correct"          "$B/user/login?username=$U&password=$PW"
p "login wrong password"   "$B/user/login?username=$U&password=wrong-$RANDOM"
p "login unknown user"     "$B/user/login?username=nouser$RANDOM&password=x"
p "updateUser anon"        -X PUT -H 'Content-Type: application/json' -d "{\"id\":$R,\"username\":\"$U\",\"firstName\":\"changed\"}" $B/user/$U
p "getUserByName after put" $B/user/$U
p "deleteUser anon"        -X DELETE $B/user/$U
p "getUserByName after del" $B/user/$U
echo "== store orders (no declared security) =="
O=$(( RANDOM % 9 + 1 ))
p "placeOrder anon"        -X POST -H 'Content-Type: application/json' -d "{\"id\":$R,\"petId\":$R,\"quantity\":1,\"status\":\"placed\"}" $B/store/order
p "getOrderById anon"      $B/store/order/$R
p "deleteOrder anon"       -X DELETE $B/store/order/$R
p "getOrderById after del" $B/store/order/$R
echo "== error handling =="
p "getOrderById non-numeric" $B/store/order/abc
p "deletePet non-numeric"  -X DELETE $B/pet/abc
p "placeOrder bad type"    -X POST -H 'Content-Type: application/json' -d '{"id":"x"}' $B/store/order
p "addPet malformed JSON"  -X POST -H 'Content-Type: application/json' -d '{' $B/pet
p "createUser bad type"    -X POST -H 'Content-Type: application/json' -d '{"id":"x"}' $B/user
p "addPet enum violation"  -X POST -H 'Content-Type: application/json' -d "{\"id\":$R,\"name\":\"sj-probe\",\"photoUrls\":[],\"status\":\"sj-not-an-enum\"}" $B/pet
p "addPet missing required" -X POST -H 'Content-Type: application/json' -d "{\"id\":$R}" $B/pet
p "cleanup pet"            -X DELETE $B/pet/$R
echo "== undeclared verbs =="
p "GET /pet"               $B/pet
p "DELETE /store/inventory" -X DELETE $B/store/inventory
p "PUT /user/login"        -X PUT $B/user/login
p "HEAD-ish TRACE /pet"    -X TRACE $B/pet
grep -i '^allow' hdr.tmp
