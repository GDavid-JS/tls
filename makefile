client=client
server=server

all:
	g++ $(client).cpp -o ./dist/$(client) -lssl -lcrypto
	g++ $(server).cpp -o ./dist/$(server) -lssl -lcrypto