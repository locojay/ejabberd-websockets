all: build

build:
	erl -pa /lib/ejabberd/ebin -pz ebin -make
install:
	cp ebin/* /lib/ejabberd/ebin;
clean:
	rm ebin/*

