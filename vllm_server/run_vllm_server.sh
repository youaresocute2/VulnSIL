#!/bin/bash
# 启动 vLLM 服务器

MODEL_DIR="/home/daiwenju/Llama-3.1-8B-Instruct"

SERVED_MODEL_NAME="Llama-3.1-8B-Instruct"

HOST="localhost"
PORT="8000"

PYTHON_PATH="/home/daiwenju/.conda/envs/vulnsil/bin/python"

export CUDA_VISIBLE_DEVICES=0

echo "Starting vLLM server for model: $SERVED_MODEL_NAME"
echo "Model path: $MODEL_DIR"
echo "Listening on: $HOST:$PORT"



$PYTHON_PATH -m vllm.entrypoints.openai.api_server \
    --model $MODEL_DIR \
    --served-model-name $SERVED_MODEL_NAME \
    --host $HOST \
    --port $PORT \
    --dtype float16 \
    --max-model-len 14480 \
    --gpu-memory-utilization 0.9 \
    --max-num-seqs 64 \
    --enable-prefix-caching \
    --disable-log-requests



