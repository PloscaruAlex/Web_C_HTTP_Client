all: client

client: client.c helpers.c parson.c
	gcc client.c helpers.c parson.c -o client

clean:
	rm -rf client