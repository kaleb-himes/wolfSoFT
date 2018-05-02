BUILD_DIR = ./Build

all: WolfSSLStaticLib wolfcrypt_test

wolfcrypt_test:
	$(MAKE) -f Makefile.test
WolfSSLStaticLib:
	$(MAKE) -f Makefile.static

clean:
	rm -f $(BUILD_DIR)/*.elf $(BUILD_DIR)/*.hex $(BUILD_DIR)/*.map
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/*.sym $(BUILD_DIR)/*.disasm
	rm -f $(BUILD_DIR)/*.a
