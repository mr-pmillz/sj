#!/usr/bin/env bash
B=https://petstore.swagger.io/v2
J='Content-Type: application/json'
R=$(( 7700000000 + RANDOM * 31 + RANDOM )); U="sjkey$RANDOM$RANDOM"
p() { local label=$1; shift; sleep 0.35; local code; code=$(curl -sS -m 20 -o body.tmp -D hdr.tmp -w '%{http_code}' "$@"); printf '%-40s %s  %s\n' "$label" "$code" "$(head -c 160 body.tmp | tr '\n' ' ')"; }
p "PUT unknown user (valid body)"  -X PUT -H "$J" -d "{\"id\":$R,\"username\":\"$U\",\"firstName\":\"sj\"}" $B/user/$U
p "GET that user"                  $B/user/$U
p "DELETE that user"               -X DELETE $B/user/$U
p "DELETE unknown user"            -X DELETE $B/user/sjnone$RANDOM$RANDOM
p "DELETE unknown order"           -X DELETE $B/store/order/$R
p "POST form unknown pet"          -X POST -d 'name=x&status=sold' $B/pet/$R
p "upload unknown pet"             -X POST -F 'additionalMetadata=sj' $B/pet/$R/uploadImage
p "login"                          "$B/user/login?username=a&password=b"
grep -i '^x-' hdr.tmp | tr -d '\r'
p "createWithArray valid"          -X POST -H "$J" -d "[{\"id\":$R,\"username\":\"$U\"}]" $B/user/createWithArray
p "cleanup array user"             -X DELETE $B/user/$U
p "findByTags no param"            "$B/pet/findByTags"
p "PUT pet unknown id"             -X PUT -H "$J" -d "{\"id\":$R,\"name\":\"sj\",\"photoUrls\":[]}" $B/pet
p "cleanup pet"                    -X DELETE $B/pet/$R
p "POST pet text/plain"            -X POST -H 'Content-Type: text/plain' -d "{\"id\":$R,\"name\":\"sj\",\"photoUrls\":[]}" $B/pet
p "POST pet empty body"            -X POST -H "$J" $B/pet
p "POST pet array body"            -X POST -H "$J" -d '["x"]' $B/pet
p "POST pet null name"             -X POST -H "$J" -d "{\"id\":$R,\"name\":null,\"photoUrls\":[]}" $B/pet
p "cleanup pet"                    -X DELETE $B/pet/$R
