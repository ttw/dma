.SUFFIXES :

aliases_t : aliases_yy.tab.o aliases_yy.lex.o aliases.o aliases_t.o
	gcc -g -o aliases_t aliases_yy.tab.o aliases_yy.lex.o aliases_t.o aliases.o

aliases_t.o : aliases_t.c
	gcc -g -c -o aliases_t.o -I.. aliases_t.c

aliases_yy.tab.c : ../aliases.y
	yacc -d -b aliases_yy -p aliases_yy ../aliases.y

aliases_yy.tab.o : aliases_yy.tab.c
	gcc -g -c -o aliases_yy.tab.o -I.. aliases_yy.tab.c \

aliases_yy.lex.c : ../aliases.l
	lex -o aliases_yy.lex.c ../aliases.l

aliases_yy.lex.o : aliases_yy.lex.c
	gcc -g -c -o aliases_yy.lex.o aliases_yy.lex.c

aliases.o : ../aliases.c
	gcc -g -c -o aliases.o ../aliases.c
