# war-compare #

You are testing a Java web application, what version is it? What is different from the one running in QA? This single file JSP drop-in allows two running web applications to compare themselves dynamically at runtime. A visual tree browser lets you drill down to find the exact files that differ between two running instances. No file data is sent, only paths and MD5 hashes.

## Requirements ##

This tool only works with applications that support JSP files.

## Installation ##

Just drop war-compare.jsp into the root directory of your web applications and navigate to the JSP. To compare two different running WARs just enter the path to the JSP in the other WAR.

## Security (optional) ##

TODO

## Future ##

Add servlet support.