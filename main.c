#include <stdio.h>
#include <stdlib.h>

int main() {
	FILE* f[10000];

	for (int i = 0; i < 10000; i++) {
		f[i] = fopen("output.txt", "w");
	}
	for (int i = 0; i < 200; i++) {
		fclose(f[i]);
	}
	printf("%d\n", 123);
}
