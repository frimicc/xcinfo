prefix=/usr/local
exec_prefix=$(prefix)
bindir=$(prefix)/bin

export prefix
export exec_prefix
export bindir

all:
	swift build -c release --arch arm64

.PHONY: all install clean cleanup

install:
	install -d $(bindir)
	install -m 0755 .build/out/Products/Release/xcinfo $(bindir)

clean:
	swift package clean

cleanup: clean
	rm -rf .build
