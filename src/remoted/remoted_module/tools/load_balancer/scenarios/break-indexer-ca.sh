# L-03 test: point the indexer connector CA at a file that does not exist, leaving
# everything else valid, and see whether the node still serves agents on 1517.
sed -i "/<indexer>/,/<\/indexer>/s|<ca>.*</ca>|<ca>etc/certs/does-not-exist.pem</ca>|" "$CONF"
echo "[override] indexer CA pointed at a missing file"
