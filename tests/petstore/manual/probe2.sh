#!/usr/bin/env bash
B=https://petstore.swagger.io/v2
p() { local label=$1; shift; sleep 0.35; local code; code=$(curl -sS -m 20 -o body.tmp -D hdr.tmp -w '%{http_code}' "$@"); printf '%-42s %s  %s\n' "$label" "$code" "$(head -c 150 body.tmp | tr '\n' ' ')"; }
J='Content-Type: application/json'
echo "== non-numeric path id (disclosure) =="
p "POST /pet/abc form"          -X POST -d 'name=x' $B/pet/abc
p "POST /pet/abc/uploadImage"   -X POST -F 'additionalMetadata=sj' $B/pet/abc/uploadImage
p "DELETE /store/order/abc"     -X DELETE $B/store/order/abc
echo "== type-invalid JSON body (server error) =="
p "PUT /pet id string"          -X PUT -H "$J" -d '{"id":"x"}' $B/pet
p "POST /user/createWithArray"  -X POST -H "$J" -d '[{"id":"x"}]' $B/user/createWithArray
p "POST /user/createWithList"   -X POST -H "$J" -d '[{"id":"x"}]' $B/user/createWithList
p "PUT /user/sjnone id string"  -X PUT -H "$J" -d '{"id":"x"}' $B/user/sjnone$RANDOM
p "createWithArray object body" -X POST -H "$J" -d '{"username":"x"}' $B/user/createWithArray
echo "== query edge cases =="
p "findByStatus no param"       "$B/pet/findByStatus"
p "findByStatus bad enum"       "$B/pet/findByStatus?status=sj-not-an-enum"
p "login no params"             "$B/user/login"
p "logout"                      "$B/user/logout"
p "getOrderById 0 (below min)"  $B/store/order/0
p "getOrderById 11 (above max)" $B/store/order/11
p "getPetById -1"               $B/pet/-1
p "getPetById overflow"         $B/pet/99999999999999999999
echo "== cleartext transport =="
p "http scheme inventory"       http://petstore.swagger.io/v2/store/inventory
grep -i '^location' hdr.tmp
