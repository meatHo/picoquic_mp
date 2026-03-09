CXX = g++
OPENSSL_PATH = /opt/homebrew/opt/openssl@3
CXXFLAGS = -I.. -I/Users/koh-mac/Documents/picotls/include -I$(OPENSSL_PATH)/include -O3 -Wall -std=c++11
LDFLAGS = ../../libpicoquic-core.a ../../libpicoquic-log.a \
          /Users/koh-mac/Documents/picotls/libpicotls-openssl.a \
          /Users/koh-mac/Documents/picotls/libpicotls-minicrypto.a \
          /Users/koh-mac/Documents/picotls/libpicotls-core.a \
          -L$(OPENSSL_PATH)/lib -lssl -lcrypto -lpthread

all: test_server test_client

test_server: test_server.cpp
	$(CXX) $(CXXFLAGS) -o test_server test_server.cpp $(LDFLAGS)

test_client: test_client.cpp
	$(CXX) $(CXXFLAGS) -o test_client test_client.cpp $(LDFLAGS)

clean:
	rm -f test_server test_client
