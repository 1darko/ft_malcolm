NAME = ft_malcolm
CC = cc
CFLAGS = -Wall -Wextra -Werror -g
RM = rm -f


SRCS = main.c

OBJS = $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

run : re
	sudo valgrind --leak-check=full ./$(NAME) 10.0.2.200 00:11:22:CC:44:Bb victim 08:00:27:E7:EB:9F -v

re: fclean all

.PHONY: all clean fclean re