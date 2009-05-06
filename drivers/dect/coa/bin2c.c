#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define HEADER_FMT \
	"/*\n"						\
	" * automatically generated file\n"		\
	" * DO NOT EDIT\n"				\
	" * edit firmware/filename.asm instead\n"	\
	" */\n"						\
	"\n"						\
	"#include \"%s.h\"\n"				\
	"\n"						\
	"const unsigned char %s[] = {\n"

#define FOOTER "};\n"

int main(int argc, char *argv[])
{
	uint32_t wordcount = 0;
	uint16_t w;
	int f;

	if (argc < 3) {
		printf("usage: bin2c bin-file varname > c-file\n");
		exit(1);
	}

	f = open(argv[1], O_RDONLY);
	if (f < 0) {
		printf("cant open(\"%s\"): %s\n", argv[1], strerror(errno));
		exit(1);
	}

	printf(HEADER_FMT, argv[2], argv[2]);

	while (2 == read(f, &w, 2)) {
		if (!wordcount)
			printf("\t");
		else
			if (!(wordcount % 4))
				printf(",\n\t");
			else
				printf(", ");
		printf("0x%.2x, 0x%.2x", (w & 0xff00) >> 8, w & 0xff);
		wordcount++;
	}
	printf(FOOTER);
	close(f);
	return 0;
}
