CXX=g++
INCLUDE_DIRS = -I./path/to \
               -I./some/other/path
               
CXXFLAGS=-O3 -std=c++11 -w $(INCLUDE_DIRS)
LDFLAGS=-pthread -lntl -lgmp -lprotobuf -lboost_system -lboost_thread

SERVER_SOURCES = ./Server/server.cpp \
                 ./Server/utils/authenticate.cpp 
                 

CLIENT_SOURCES = ./Client/client.cpp \
                 ./Client/utils/authenticate.cpp 
                

all: server client

server: $(SERVER_SOURCES)
	$(CXX) $(CXXFLAGS) $^ -o $@ -lssl -lcrypto $(LDFLAGS) -Wno-deprecated-declarations

client: $(CLIENT_SOURCES)
	$(CXX) $(CXXFLAGS) $^ -o $@ -lssl -lcrypto $(LDFLAGS) -Wno-deprecated-declarations

.PHONY: clean run_server run_client

clean:
	rm -f server client

run_server: server
	./server

run_client: client
	./client
