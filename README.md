# BPIA: Block Process Internet Access

## Summary

BPIA is a program that can be used to block currently running processes from accessing the internet on a windows computer. It does this by adding and removing filters from the Windows Filtering Platform. As such any rules added by the program remain until explicitly removed.

## How to Build

Install the windows platform SDK if you do not have it installed

Clone the repository

Run 'make' in the terminal

```
$ make
```


## How to Use

To run the program, use one of the commands listed below in a terminal that is running as an administator. 

To add or remove a filter for an application (a process with an associated window):

```
./bpia
```

To add or remove a filter for a process

```
./bpia -p
```

To see all filters currently in the windows filtering platform

```
./bpia -f
```

To see all filters on the layers of the windows filtering platform used by this program

For IPv4 filters

```
./bpia -f default_v4
```

For IPv6 filters

```
./bpia -f default_v6
```