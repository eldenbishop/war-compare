# war-compare #

An extermely ugly but effective hack to allow two running WAR applications to dynamically compare themselves at runtime. I whipped this up in an hour or two several years ago and have found this a very nice file to chuck into my web applications.

You are testing a Java web application, what version is it? What is different from the one running in QA? This single file JSP drop-in allows two running web applications to compare themselves dynamically at runtime. A visual tree browser lets you drill down to find the exact files that differ between two running instances. No file data is sent, only paths and MD5 hashes.

## Requirements ##

This tool only works with applications that support JSP files.

## Installation ##

Just drop md5.jsp into the root directory of your web applications and navigate to the JSP. To compare two different running WARs just enter the path to the JSP in the other WAR.

## Security (optional) ##

TODO

## Future ##

Add servlet support.