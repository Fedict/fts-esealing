export HOST=${HOST:-localhost}
export PORT=${PORT:-8080}
export USERNAME=${USERNAME:-selor}
export PASS=${PASS:-test123}

printf "==== List request ====\n"
curl -X POST --user $USERNAME:$PASS -H "Content-type: application/json; charset=UTF-8" --data-binary @esealing-ws/samples/listreq.json http://$HOST:$PORT/esealing/credentials/list

printf "\n\n==== Info request ====\n"
curl -X POST --user $USERNAME:$PASS -H "Content-type: application/json; charset=UTF-8" --data-binary @esealing-ws/samples/inforeq.json http://$HOST:$PORT/esealing/credentials/info

printf "\n\n==== Sign request ====\n"
curl -X POST --user $USERNAME:$PASS -H "Content-type: application/json; charset=UTF-8" --data-binary @esealing-ws/samples/signreq.json http://$HOST:$PORT/esealing/signatures/signHash

printf "\n\n"
