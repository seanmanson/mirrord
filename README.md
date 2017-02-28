mirrord
=======

A simple event-driven HTTP/1.0 server daemon in C for POSIX systems for hosting files.
Created as an assessment piece for UQ's 2015 COMP3301 course.

*For more information, see `assignment1.pdf`*

Usage
-----
```
mirrord [-46d] [-a access.log] [-l address] [-p port] directory
```
where:
 - `-4`: IPv4 only
 - `-6`: IPv6 only
 - `-a access.log`: Log requests to this file. No logging by default.
 - `-d`: Do not demonise. Output will be redirected to stdout, ignoring `-a`.
 - `-l address`: Listen on this address for requests. By default, wildcard.
 - `-p port`: Listed on this port. By default, this depends on the system default for HTTP.
 - `directory`: The directory with files to host.
