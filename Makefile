CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread -Iinclude $(shell pkg-config --cflags libsodium)
LDFLAGS = -pthread $(shell pkg-config --libs libsodium)
ifeq ($(shell uname -s),Darwin)
LDFLAGS += -lproc
endif

TARGET = secure_cipher

SRC = \
	main.cpp \
	crypto/context.cpp \
	crypto/path.cpp \
	crypto/kdf.cpp \
	crypto/header.cpp \
	crypto/keystore.cpp \
	crypto/encrypt.cpp \
	crypto/decrypt.cpp \
	crypto/stream_io.cpp \
	crypto/work_pool.cpp \
	cli/parser.cpp \
	platform/posix.cpp \
	platform/macos.cpp \
	platform/linux.cpp \
	platform/windows.cpp \
	anti_analysis/audit.cpp \
	anti_analysis/vm_guard.cpp

OBJ = $(SRC:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJ)
