# in the sdk root folder (eg., ~/sdk)

docker run \
--name monitoring \
-d \
--network host \
-v "$(pwd):/workspace" \
ubuntu:stonking-20260612 \
/bin/sh /workspace/examples/coins-chain/monitoring/run.sh
