#!/bin/bash
if [[ $# -ne 1 ]]; then
	echo "Usage $0 <router port>"
	exit 1
fi

# Use this command when testing with k8s service discovery
# vllm-router --port "$1" \
#     --service-discovery k8s \
#     --k8s-label-selector release=test \
#     --k8s-namespace default \
#     --routing-logic session \
#     --session-key "x-user-id" \
#     --engine-stats-interval 10 \
#     --log-stats

# Use this command when testing with static service discovery
uv run app.py --port "$1" \
	--service-discovery url \
	--discovery-url "http://51.91.160.170:8080/models/by-model" \
	--discovery-refresh-interval 30 \
	--static-model-types "chat" \
	--log-stats \
	--log-stats-interval 10 \
	--engine-stats-interval 10 \
	--request-stats-window 10 \
	--routing-logic prefixaware

# Use this command when testing with roundrobin routing logic
#vllm-router --port "$1" \
#    --service-discovery k8s \
#    --k8s-label-selector release=test \
#    --routing-logic roundrobin \
#    --engine-stats-interval 10 \
