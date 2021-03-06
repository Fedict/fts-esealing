export HOST=${HOST:-localhost}
export PORT=${PORT:-8080}
export USERNAME=${USERNAME:-selor}
export PASS=${PASS:-test123}
export PROTO=${PROTO:-http}

printf "==== List request ====\n"
curl -k -X POST --user $USERNAME:$PASS -H "Content-type: application/json; charset=UTF-8" --data-binary @esealing-ws/samples/listreq.json $PROTO://$HOST:$PORT/esealing/credentials/list

printf "\n\n==== Info request ====\n"
curl -k -X POST --user $USERNAME:$PASS -H "Content-type: application/json; charset=UTF-8" --data-binary @esealing-ws/samples/inforeq.json $PROTO://$HOST:$PORT/esealing/credentials/info

printf "\n\n==== Sign request ====\n"
curl -k -X POST --user $USERNAME:$PASS -H "Content-type: application/json; charset=UTF-8" --data-binary @esealing-ws/samples/signreq.json $PROTO://$HOST:$PORT/esealing/signatures/signHash

printf "\n\n"
