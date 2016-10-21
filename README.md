meminfo
=======

meminfo was born out of a need to report large system memory usage in
some meaningful way. ps and top have their uses, as do others, but they
have two problems (in my opinion):

1. They don't show URES (unique resident set size)

2. The information they provide is of limited value once you start having
   1000+ processes on a multi-user system

meminfo fills the gap (or aims to at least).

Limitations
-----------

meminfo has only been tested on Linux systems and will require significant
rework to be useful on other UNIX-like systems.

Tested on 2.6 kernels and one 2.4 system (debian 3.1)

License
-------

meminfo is copyright Aleksandr Koltsoff.

meminfo is released under the GPLv2 in the hopes that it may be of use
to other people (please see the accompanying COPYING file, or if the file
is missing [bad!] you can find it at http://www.gnu.org/licenses/gpl.txt).

The license and sourcecode is also available at:
https://github.com/majava3000/meminfo

Operation
---------

meminfo generates three lists according to real memory usage:

* The first is sorted by URES per process
* The second one groups processes according to usernames and sorts that based on ures
* The third groups based on process names and again sorts based on total ures
* Fourth is optional and depends whether you have SMP-system or not
  tries to group memory and runtimes according to logical CPUs
  if you don't have SMP (enabled), you won't see the fourth report
  and the first report will be missing the C#-field (CPU that last
  executed a process).

For explanation on URES, please see http://koltsoff.com/pub/ures/

Feel free to fork the project and send pull requests via github.

Hope you find it useful, I sure did,

Aleksandr Koltsoff
2006-09-28
