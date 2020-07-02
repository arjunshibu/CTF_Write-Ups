#include <stdio.h>
#include <stdbool.h>

int main()
{
	bool flag = true;
	if (flag && !flag)
	{
		printf("done");
	} else
		printf("%d", flag);
}