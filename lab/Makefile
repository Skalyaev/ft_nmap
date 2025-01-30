SHELL:=/bin/bash
COMPOSE=compose.yaml

all: build up

build:
	docker compose -f $(COMPOSE) build

up:
	docker compose -f $(COMPOSE) up

down:
	docker compose -f $(COMPOSE) down

re: down all

clean:
	-docker rm $$(docker ps -a | grep Exited | awk '{print $1}')
	-docker rmi $$(docker images | grep '<none>' | awk '{print $3}')

fclean:
	docker system prune -fa

.PHONY: all build up down re clean fclean
