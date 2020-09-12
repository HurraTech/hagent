#!/bin/bash
protoc -I . hurra_agent.proto --go_out=plugins=grpc:./proto 
protoc -I . hurra_agent.proto --go_out=plugins=grpc:../../jawhar/internal/agent/proto
grpc_tools_ruby_protoc -I . --ruby_out=../jawhar/lib/hurracloud-agent --grpc_out=../jawhar/lib/hurracloud-agent hurra_agent.proto
# cp hurra_agent.proto ../jawhar/
