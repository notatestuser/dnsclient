/* 
 * File:   commands.c
 * Author: Luke Plaster
 */

#include "stdafx.h"

int command_opt_set(const char *opt, int argc, char *argv[])
{
	int i;
	for (i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], opt) == 0)
			return 1;
	}
	return 0;
}

char *command_arg_get(int order, const char switchTrigger, int argc, char *argv[])
{
	int i, curOrder = 0;
	for (i = 1; i < argc; i++)
	{
		if (*argv[i] != switchTrigger)
		{
			if (curOrder == order)
			{
				return argv[i];
			}
			curOrder++;
		}
	}
	return NULL;
}
