protoc -I . --grpc_out=. --plugin=protoc-gen-grpc=/usr/local/bin/grpc_cpp_plugin  yak.proto
protoc -I .   --cpp_out=.   yak.proto