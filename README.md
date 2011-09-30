# war-compare #

An extermely simple single file drop-in that allows two WAR applications to dynamically compare themselves at runtime.
This is done via direct communication between running applications, no access to the file system of either machine is
required.

Say you are testing a Java web application, what version is it? What is different from the one running in QA?
What files, classes or jars have changed? A visual tree browser lets you drill down to find the exact files that
differ between two running instances. No file data is sent, only paths and MD5 hashes.

## Requirements ##

This tool only works with applications that support JSP files.

## Installation ##

Just drop md5.jsp into the root directory of your web applications.

## Usage ##

Simply navigate to the JSP. Once there, enter a path to another md5.jsp. The two files will communicate with each other,
allowing visual navigation of both file trees along with MD5 hashing for realtime diffs.

## Security (optional) ##

Security is documented inside the JSP. A sample properties file is included in the project.

## Future ##

Add servlet support for containers/projects that do not use JSP.