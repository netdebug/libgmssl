SM2OBJ=sm2_lib.o sm2_asn1.o sm2_err.o sm2_sign.o sm2_enc.o sm2_kap.o kdf_x9_63.o
SM3OBJ=sm3.o m_sm3.o
SM4OBJ=sms4_cbc.o sms4_cfb.o sms4_ecb.o sms4_ofb.o sms4_ctr.o sms4_wrap.o sms4.o e_sms4.o
TEST=gm sm2 sm4
ALL=libgmssl.so $(TEST)

CFLAGS=-ggdb3 -fPIC -Wall

all: $(ALL)

# %.o: %.c
#	gcc -c -fPIC -Wall -ggdb3 -o $@ $+ -I$(OPENSSL_ROOT)/include
OPENSSL_ROOT=$(HOME)/gxp/deps/openssl
# #OPENSSL_ROOT=/usr
# OPENSSL_ROOT=$(CODEBASELOCAL)
test:gm sm2 sm4
	LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH ./gm
	LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH ./sm2
	LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH ./sm4
gm: gmtest.o libgmssl.so
	gcc -o $@ $< -I$(OPENSSL_ROOT)/include -L$(OPENSSL_ROOT)/lib -lcrypto -ldl -L. -lgmssl

sm4: sms4test.o
	gcc -o $@ $+ -I$(OPENSSL_ROOT)/include -L$(OPENSSL_ROOT)/lib -lcrypto -ldl -L. -lgmssl

sm2: sm2test.o
	gcc -o $@ $+ -I$(OPENSSL_ROOT)/include -L$(OPENSSL_ROOT)/lib -lcrypto -ldl -L. -lgmssl

libgmssl.so: $(SM2OBJ) $(SM3OBJ) $(SM4OBJ)
	gcc -o $@ $+ -fPIC -shared -I$(OPENSSL_ROOT)/include -L$(OPENSSL_ROOT)/lib -lcrypto

clean:
	rm -rf $(ALL) *.o
