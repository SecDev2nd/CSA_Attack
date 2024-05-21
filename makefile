LDLIBS += -lpcap

all: csa_atk

deauth_attack: src/csa_atk.cpp

clean:
	rm -f csa_atk *.o