# 
#  NOTICE
# 
#  The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
#  If you choose to receive it under the GPL v.3 license, the following applies:
#  Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
#  
#  Copyright (C) 2018-2019, Unbound Tech Ltd. 
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
# 

# ---------------- protobuf and grpc -------------------------


PROTOC = protoc
GRPC_CPP_PLUGIN = grpc_cpp_plugin
GRPC_CPP_PLUGIN_PATH ?= `which $(GRPC_CPP_PLUGIN)`

PROTOS_PATH = leath/protos/

vpath %.proto $(PROTOS_PATH)

all: system-check

PROTOC_CMD = which $(PROTOC)
PROTOC_CHECK_CMD = $(PROTOC) --version | grep -q libprotoc.3
PLUGIN_CHECK_CMD = which $(GRPC_CPP_PLUGIN)
HAS_PROTOC = $(shell $(PROTOC_CMD) > /dev/null && echo true || echo false)
ifeq ($(HAS_PROTOC),true)
HAS_VALID_PROTOC = $(shell $(PROTOC_CHECK_CMD) 2> /dev/null && echo true || echo false)
endif
HAS_PLUGIN = $(shell $(PLUGIN_CHECK_CMD) > /dev/null && echo true || echo false)

SYSTEM_OK = false
ifeq ($(HAS_VALID_PROTOC),true)
ifeq ($(HAS_PLUGIN),true)
SYSTEM_OK = true
endif
endif

system-check:
ifneq ($(HAS_VALID_PROTOC),true)
	@echo " DEPENDENCY ERROR"
	@echo
	@echo "You don't have protoc 3.0.0 installed in your path."
	@echo "Please install Google protocol buffers 3.0.0 and its compiler."
	@echo "You can find it here:"
	@echo
	@echo "   https://github.com/google/protobuf/releases/tag/v3.0.0"
	@echo
	@echo "Here is what I get when trying to evaluate your version of protoc:"
	@echo
	-$(PROTOC) --version
	@echo
	@echo
endif
ifneq ($(HAS_PLUGIN),true)
	@echo " DEPENDENCY ERROR"
	@echo
	@echo "You don't have the grpc c++ protobuf plugin installed in your path."
	@echo "Please install grpc. You can find it here:"
	@echo
	@echo "   https://github.com/grpc/grpc"
	@echo
	@echo "Here is what I get when trying to detect if you have the plugin:"
	@echo
	-which $(GRPC_CPP_PLUGIN)
	@echo
	@echo
endif
ifneq ($(SYSTEM_OK),true)
	@false
endif

# ---------------- COMMON -------------------------
COMMON_INCLUDES = \
	-I include

COMMON_CPPFLAGS = \
	-O2 \
	-fPIC \
	-fno-strict-aliasing \
	-Wno-unused \
	-Wno-switch \
	-Wno-switch-enum \
	-Werror \
	-mpclmul \
	-std=c++0x

COMMON_LDFLAGS = \
	-s

#---------------- LIB -------------------
	
LIB_CPPSRC = $(wildcard src/*.cpp) \
	$(wildcard src/utils/*.cpp) \
	$(wildcard src/crypto_utils/*.cpp) \
	$(wildcard src/mpc_protocols/*.cpp) \
	$(wildcard src/leath/*.cpp) \
	$(wildcard src/leath/protos/*.cpp)
		 
LIB_ASMSRC = \
	$(wildcard src/mpc_protocols/*.s)
		 
LIB_OBJ = \
	$(LIB_CPPSRC:.cpp=.o) \
	$(LIB_ASMSRC:.s=.o) 

LIB_HEADERS = $(wildcard src/*.h) \
	$(wildcard src/utils/*.h) \
	$(wildcard src/crypto_utils/*.h) \
	$(wildcard src/mpc_protocols/*.h) \
	$(wildcard src/leath/*.h) \
	$(wildcard src/leath/protos/*.h)
	
LIB_INCLUDES = \
	$(COMMON_INCLUDES) \
	-I ${JAVA_HOME}/include \
	-I ${JAVA_HOME}/include/linux \
	-I src/utils \
	-I src/crypto_utils \
	-I src/mpc_protocols \
	-I src/leath \
	-I src/leath/protos
	

LIB_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	-DMPC_CRYPTO_EXPORTS \
	-fvisibility=hidden \
	-maes

LIB_LDFLAGS = \
	$(COMMON_LDFLAGS) \
	-Wl,-z,defs \
	-Wl,-rpath,\'\$$ORIGIN\' \
	-shared \
	-rdynamic \
	-lcrypto \
	-lpthread \
	-lprotobuf \
	-lz \
	-lgrpc \
	-lgrpc++

.s.o: 
	$(CXX) -o $@ -c $<

src/utils/precompiled.h.gch: src/utils/precompiled.h
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

src/utils/%.o: src/utils/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<
   
src/crypto_utils/%.o: src/crypto_utils/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

src/mpc_protocols/%.o: src/mpc_protocols/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

src/leath/%.o: src/leath/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

src/leath/protos/%.o: src/leath/protos/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<


src/%.o: src/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

libmpc_crypto.so: $(LIB_OBJ)
	$(CXX) -o $@ $^ $(LIB_LDFLAGS)


#----------------------- TEST --------------------------	
	
TEST_SRC = \
	$(wildcard test/*.cpp)

TEST_OBJ = \
	$(TEST_SRC:.cpp=.o)
	
TEST_CPPFLAGS = \
	$(COMMON_CPPFLAGS)
  
TEST_INCLUDES = \
	$(COMMON_INCLUDES) \
	-I src \
	-I src/protos \
	-I src/mpc_protocols \
	-I src/crypto_utils \
	-I src/utils
	
TEST_LDFLAGS = \
	$(COMMON_LDFLAGS) \
	-L . \
	-lmpc_crypto



test/%.o: test/%.cpp
	$(CXX) $(TEST_CPPFLAGS) $(TEST_INCLUDES) -o $@ -c $<


mpc_crypto_test: $(TEST_OBJ) libmpc_crypto.so# leath.pb.cpp  leath.grpc.pb.cpp
	$(CXX) -o $@ $^ $(TEST_LDFLAGS)

#----------------------- BENCH --------------------------	
	
BENCH_SRC = \
	$(wildcard bench/*.cpp)

BENCH_OBJ = \
	$(BENCH_SRC:.cpp=.o)
	
BENCH_CPPFLAGS = \
	$(COMMON_CPPFLAGS)
  
BENCH_INCLUDES = \
	$(COMMON_INCLUDES) \
	-I src

BENCH_LDFLAGS = \
	$(COMMON_LDFLAGS) \
	-L . \
	-lmpc_crypto

  
bench/%.o: bench/%.cpp
	$(CXX) $(BENCH_CPPFLAGS) $(BENCH_INCLUDES) -o $@ -c $<

mpc_crypto_bench: $(BENCH_OBJ) libmpc_crypto.so
	$(CXX) -o $@ $^ $(BENCH_LDFLAGS)



#----------------------- LEATH --------------------------	
	
# LEATH_SRC = \
# 	$(wildcard leath/*.cpp)\
# 	$(wildcard leath/protos/*.cpp)

# LEATH_OBJ = \
# 	$(LEATH_SRC:.cpp=.o)

# LEATH_CPPFLAGS = \
# 	$(COMMON_CPPFLAGS)
  
# LEATH_INCLUDES = \
# 	$(COMMON_INCLUDES) \
# 	-I src \
# 	-I src/mpc_protocols\
# 	-I src/utils \
# 	-I src/crypto_utils \
# 	-I leath/protos \
# 	-I leath

# LEATH_LDFLAGS = \
# 	$(COMMON_LDFLAGS) \
# 	-L . \
# 	-lmpc_crypto\
# 	-lprotobuf \
# 	-lz\
# 	-lgrpc \
# 	-lgrpc++\
# 	-lpthread\
# 	-std=c++0x


# .PRECIOUS: %.grpc.pb.cpp
# %.grpc.pb.cpp: %.proto
# 	$(PROTOC) -I $(PROTOS_PATH) --grpc_out=./leath/protos --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN_PATH) $<

# .PRECIOUS: %.pb.cpp
# %.pb.cpp: %.proto
# 	$(PROTOC) -I $(PROTOS_PATH) --cpp_out=./leath/protos $<


# leath/protos/%.o: %.pb.cpp %.grpc.pb.cpp
# 	$(CXX) $(LEATH_CPPFLAGS) $(LEATH_INCLUDES) -o $@ -c $<

# leath/%.o: leath/%.cpp 
# 	$(CXX) $(LEATH_CPPFLAGS) $(LEATH_INCLUDES) -o $@ -c $<

# test_leath_client_server: $(LEATH_OBJ) #libmpc_crypto.so
# 	$(CXX) -o $@ $^ $(LEATH_INCLUDES) $(LEATH_LDFLAGS) 


# leath_client: $(LEATH_OBJ) libmpc_crypto.so # leath.grpc.pb.o leath.pb.o  
# 	$(CXX) -o $@ $^ $(LEATH_LDFLAGS)

# leath_server: $(LEATH_OBJ) libmpc_crypto.so
# 	$(CXX) -o $@ $^ $(LEATH_LDFLAGS)
#---------------------------------------------------------




.PHONY: clean

clean:
	rm -f $(LIB_OBJ) $(TEST_OBJ) $(LEATH_OBJ)  mpc_crypto_test mpc_crypto_bench libmpc_crypto.so src/utils/precompiled.h.gch
	
.DEFAULT_GOAL := mpc_crypto_test #leath_server #mpc_crypto_test
