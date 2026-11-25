#!/usr/bin/env bash
# Independent curl checks of rows sj reported beyond the original answer key.
B=https://petstore.swagger.io/v2
J='Content-Type: application/json'; A='Accept: application/json'
R=$(( 7700000000 + RANDOM * 31 + RANDOM )); U="sjkey$RANDOM$RANDOM"
p() { local label=$1; shift; sleep 0.35; local code; code=$(curl -sS -m 20 -o body.tmp -w '%{http_code}' "$@"); printf '%-44s %s  %s\n' "$label" "$code" "$(head -c 210 body.tmp | tr '\n' ' ')"; }
echo "== 415 disclosure (text/plain body, Accept JSON) =="
p "POST /store/order text/plain"   -X POST -H "$A" -H 'Content-Type: text/plain' -d '{"id":1}' $B/store/order
p "POST /user text/plain"          -X POST -H "$A" -H 'Content-Type: text/plain' -d '{"id":1}' $B/user
p "POST /user/createWithArray t/p" -X POST -H "$A" -H 'Content-Type: text/plain' -d '[]' $B/user/createWithArray
p "POST /user/createWithList t/p"  -X POST -H "$A" -H 'Content-Type: text/plain' -d '[]' $B/user/createWithList
p "PUT /user/x text/plain"         -X PUT  -H "$A" -H 'Content-Type: text/plain' -d '{"id":1}' $B/user/sjnone$RANDOM
p "POST /pet text/plain"           -X POST -H "$A" -H 'Content-Type: text/plain' -d '{"id":1}' $B/pet
p "PUT /pet text/plain"            -X PUT  -H "$A" -H 'Content-Type: text/plain' -d '{"id":1}' $B/pet
echo "== contract-violating input accepted =="
p "POST /store/order status enum"  -X POST -H "$J" -d "{\"id\":$R,\"petId\":1,\"quantity\":1,\"status\":\"sj-not-an-enum\"}" $B/store/order
p "cleanup order"                  -X DELETE $B/store/order/$R
p "POST /user email as number"     -X POST -H "$J" -d "{\"id\":$R,\"username\":\"$U\",\"email\":9173}" $B/user
p "GET that user"                  $B/user/$U
p "PUT /user firstName as number"  -X PUT -H "$J" -d "{\"id\":$R,\"username\":\"$U\",\"firstName\":9173}" $B/user/$U
p "cleanup user"                   -X DELETE $B/user/$U
p "createWithArray email number"   -X POST -H "$J" -d "[{\"id\":$R,\"username\":\"$U\",\"email\":9173}]" $B/user/createWithArray
p "cleanup user"                   -X DELETE $B/user/$U
p "PUT /pet without name"          -X PUT -H "$J" -d "{\"id\":$R,\"photoUrls\":[]}" $B/pet
p "cleanup pet"                    -X DELETE $B/pet/$R
echo "== record left by a coerced identifier =="
p "GET /user/9173"                 $B/user/9173
p "DELETE /user/9173"              -X DELETE $B/user/9173
