# Host tests: the C core (with ASan + UBSan, as gadget-sso does) and the
# Python CLI's offline helpers. No ESP-IDF, no board, no network.
CC ?= cc
CORE := components/workos_cloud
CJSON := tests/vendor/cJSON
OUT := .build/tests
CFLAGS := -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined -fno-sanitize-recover=undefined

.PHONY: test test-core test-cli example clean

test: test-core test-cli

test-core: $(OUT)/test_core
	$(OUT)/test_core

# Vendored cJSON is third-party: sanitized, but not held to -Werror.
$(OUT)/cJSON.o: $(CJSON)/cJSON.c $(CJSON)/cJSON.h
	@mkdir -p $(OUT)
	$(CC) -std=c11 -g -w -fsanitize=address,undefined -c $< -o $@

$(OUT)/test_core: tests/test_core.c $(wildcard $(CORE)/core/*.c) $(wildcard $(CORE)/include/*.h) $(OUT)/cJSON.o
	$(CC) $(CFLAGS) -I$(CORE)/include -I$(CJSON) tests/test_core.c $(CORE)/core/*.c $(OUT)/cJSON.o -lm -o $@

test-cli:
	python3 -I -m unittest discover -s tests -p 'test_*.py' -q

# Compile examples/minimal for esp32s3 (needs ESP-IDF: . ~/esp/esp-idf-v6.0.1/export.sh).
example:
	cd examples/minimal && { [ -f sdkconfig ] || idf.py set-target esp32s3; } && idf.py build

clean:
	rm -rf .build
