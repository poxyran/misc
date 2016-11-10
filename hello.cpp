#include <stdio.h>
#include <windows.h>

__declspec(noinline) void f(int n)
{
	printf("Number: %d\n", n);
}

int main(int argc, char * argv[])
{
	int i = 0;

	printf("f() is at %p\n", f);

	while (1)
	{
		f(i++);
		Sleep(1);
	}

	return 0;
}