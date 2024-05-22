LDLIBS += -lpcap

all: csa_atk csa_atk2

csa_atk: src/csa_atk.cpp
	g++ -o csa_atk src/csa_atk.cpp $(LDLIBS)

csa_atk2: src/csa_atk2.cpp
	g++ -o csa_atk2 src/csa_atk2.cpp $(LDLIBS)
clean:
	rm -f csa_atk csa_atk2 *.o