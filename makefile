LDLIBS += -lpcap

all: csa_atk

csa_atk: src/csa_atk.cpp
	g++ -o csa_atk src/csa_atk.cpp $(LDLIBS)

clean:
	rm -f csa_atk *.o