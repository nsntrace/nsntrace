/*
 * nsntrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * nsntrace is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with nsntraces; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdarg.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * This function aims to transform a command in string format to a format of:
 *
 * array[0]     = "cmd";
 * array[1]     = "argument1";
 * array[2)     = "argument2";
 * array[N]     = "argumentN";
 * array[N + 1] = NULL;
 *
 * Which is the expected format of the exec() family of functions.
 */
static void
_nsntrace_cmd_parse(char *line, char **argv)
{
	while (*line != '\0') {
		while (*line == ' ' || *line == '\t' || *line == '\n') {
			*line++ = '\0';
		}
		*argv++ = line;
		while (*line != '\0' && *line != ' ' &&
		       *line != '\t' && *line != '\n')
			line++;
	}
	*argv = '\0';
}

/*
 * Run a command and wait for it to finish. We use the magic va_list and
 * va_start to make this behave like a printf style function. Returns the
 * exit code of the command.
 */
int
nsntrace_cmd_run(char *format, ...)
{
	pid_t pid = fork();

	if (pid < 0) {
		return pid;
	} else if (pid > 0) { /* parent */
		int status;

		waitpid(pid, &status, 0);
		return WEXITSTATUS(status);
	} else { /* child */
		char *args[64];
		char cmd[1024];
		va_list arg;

		va_start(arg, format);
		vsnprintf(cmd, 1024, format, arg);
		_nsntrace_cmd_parse(cmd, args);
		execvp(args[0], args);
	}
}
