#!/usr/bin/env bash
# Which input makes uploadImage answer 500: the unknown pet or the missing file part?
B=https://petstore.swagger.io/v2
J='Content-Type: application/json'; A='Accept: application/json'
R=$(( 7700000000 + RANDOM * 31 + RANDOM )); G=$(( 7800000000 + RANDOM * 31 + RANDOM )); U="sjkey$RANDOM$RANDOM"
p() { local label=$1; shift; sleep 0.35; local code; code=$(curl -sS -m 20 -o body.tmp -D hdr.tmp -w '%{http_code}' "$@"); printf '%-46s %s  %s\n' "$label" "$code" "$(head -c 260 body.tmp | tr '\n' ' ')"; }
p "create pet"                               -X POST -H "$J" -d "{\"id\":$R,\"name\":\"sj-probe\",\"photoUrls\":[]}" $B/pet
p "upload: existing pet, file + metadata"    -X POST -H "$A" -F 'additionalMetadata=sj' -F 'file=@probe4.sh;filename=sj.txt;type=text/plain' $B/pet/$R/uploadImage
p "upload: existing pet, metadata only"      -X POST -H "$A" -F 'additionalMetadata=sj' $B/pet/$R/uploadImage
grep -i '^content-type' hdr.tmp | tr -d '\r'; grep -o -i 'jetty[^<]*' body.tmp | head -3
p "upload: existing pet, file only"          -X POST -H "$A" -F 'file=@probe4.sh;filename=sj.txt;type=text/plain' $B/pet/$R/uploadImage
p "upload: existing pet, no body"            -X POST -H "$A" $B/pet/$R/uploadImage
p "upload: unknown pet, file + metadata"     -X POST -H "$A" -F 'additionalMetadata=sj' -F 'file=@probe4.sh;filename=sj.txt;type=text/plain' $B/pet/$G/uploadImage
p "form update: existing pet, no fields"     -X POST -H "$A" -H 'Content-Type: application/x-www-form-urlencoded' $B/pet/$R
p "form update: existing pet, name only"     -X POST -H "$A" -d 'name=sj-form' $B/pet/$R
p "cleanup pet"                              -X DELETE $B/pet/$R
echo "== body identity differs from the path =="
p "create user"                              -X POST -H "$J" -d "{\"id\":$R,\"username\":\"$U\",\"firstName\":\"a\"}" $B/user
p "PUT /user/U with username U-renamed"      -X PUT -H "$J" -d "{\"id\":$R,\"username\":\"$U-renamed\",\"firstName\":\"b\"}" $B/user/$U
p "GET /user/U"                              $B/user/$U
p "GET /user/U-renamed"                      $B/user/$U-renamed
p "cleanup U"                                -X DELETE $B/user/$U
p "cleanup U-renamed"                        -X DELETE $B/user/$U-renamed
# This request ran once on 2026-11-25. The service stored a user that has no
# username and cannot be deleted, so it stays disabled.
# p "POST /user username null"               -X POST -H "$J" -d "{\"id\":$R,\"username\":null}" $B/user
