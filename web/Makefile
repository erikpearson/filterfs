# Generate web page

.PHONY: all clean
all: index.html

clean:
	rm -f index.html

index.html: ../README
	@echo "  GEN   " $@
	@rst2html --stylesheet=voidspace.css --link-stylesheet $< $@
