/* 
 * File:   commands.h
 * Author: Luke Plaster
 */

#pragma once

/* Checks an array of command line arguments to test if the specified argument flag is set */
/* Returns: boolean */
int command_opt_set(const char *opt, int argc, char *argv[]);

/* Returns a pointer to the argument specified in the order index */
char *command_arg_get(int order, const char switchTrigger, int argc, char *argv[]);
