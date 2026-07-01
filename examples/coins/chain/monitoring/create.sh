# run from current folder (examples/coins/chain/monitoring)

docker stop monitoring 2>/dev/null || true
docker rm monitoring 2>/dev/null || true

docker run \
--name monitoring \
-it \
--network host \
-v "$(pwd):/workspace" \
ubuntu:stonking-20260612 \
/bin/sh /workspace/run.sh
