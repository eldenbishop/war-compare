<%@page contentType="text/html" pageEncoding="UTF-8" import="java.security.MessageDigest,java.net.URL,java.net.URLConnection,java.util.*,java.io.*"%>
<%!

/*
 * This ugly file is a simple self contained MD5 directory crawler and diff console.
 *
 * Installing: Just drop this JSP in directory you want to support MD5 scans.
 *
 * Usage: Open a web browser and navigate to this file.
 *        Enter another md5.jsp in the form to do a diff.
 *
 * Configuration: You can set up md5.jsp to ignore certain directories by
 *     creating an md5.properties file in the same directory as md5.jsp.
 *     This file should look something like this.
 *
 *     --- md5.properties start ---
 *     ignore=WEB-INF/classes,images,tools/3rdparty
 *     secure=true
 *     users=md5:md5pass,joe:joepass
 *     --- md5.properties end ---
 *
 *     The above will ignore those three paths when calculating diffs which can
 *     significantly speed up the calculations.
 *     NOTE: The ignored paths can be a file or a directory.
 *
 *     The JSP will search UP the directory tree, loading all of the md5
 *     property files it finds along the way. This means you can put a file
 *     that ignores a directory while further up putting a single file that
 *     turns on security and adds some users. Paths are relative to the properties
 *     file, not the jsp.
 *
 *     Finally, '${user.home}/.war-compare/md5.properties' is also loaded and
 *     applied. Ignore paths set here must be absolute to work. This is a good
 *     place to put all of your users as it is centralized and easy to manage.
 *
 *     NOTE: ALL md5 property files are loaded and applied. If any file turns
 *     on security, it stays on.
 *
 *     NOTE: If security is enabled but no users are defined a default user
 *     name 'md5' with password 'md5pass' is created. This guarantees the
 *     service is always reachable.
 *
 */
  static public char[] hexChars = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
  static public String toHex(final byte[] bytes) {
      StringBuilder sb = new StringBuilder();
      for (byte b : bytes) {
          sb.append(hexChars[b >= 0 ? (b >>> 4) : (8 + ((128 + b) >>> 4))]);
          sb.append(hexChars[b & 0xF]);
      }
      return sb.toString();
  }
  static Map<String,Diff> parseTarget(String userPass, String targetUrl, String targetBase, String targetPath) throws Exception {
      Map<String,Diff> rval = new TreeMap<String,Diff>();
      URL url = new URL(targetUrl + "?" + (targetBase == null ? "" : "base=" + targetBase + "&") + (targetPath == null ? "" : "path=" + targetPath + "&"));
      URLConnection uc = url.openConnection();
      if (isNotBlank(userPass)) {
          uc.setRequestProperty("authorization", "Basic " + new sun.misc.BASE64Encoder().encode(userPass.getBytes()));
      }
      BufferedReader in = new BufferedReader(new InputStreamReader(uc.getInputStream()));
      String inputLine = null;
      long length = 0;
      Boolean isDir = null;
      String csum = null;
      String path = null;
      while ((inputLine = in.readLine()) != null) {
          if (inputLine.contains("class=\"isDir\"")) {
              int isDirIndex = inputLine.indexOf(">", inputLine.indexOf("class=\"isDir\""));
              isDir = new Boolean(inputLine.substring(isDirIndex + 1, inputLine.indexOf("<", isDirIndex)));
          }
          if (inputLine.contains("class=\"len\"")) {
              int lenIndex = inputLine.indexOf(">", inputLine.indexOf("class=\"len\""));
              length = Long.parseLong(inputLine.substring(lenIndex + 1, inputLine.indexOf("<", lenIndex)));
          }
          if (inputLine.contains("class=\"csum\"")) {
              int csumIndex = inputLine.indexOf(">", inputLine.indexOf("class=\"csum\""));
              csum = inputLine.substring(csumIndex + 1, inputLine.indexOf("<", csumIndex));
          }
          if (inputLine.contains("class=\"path\"")) {
              int pathIndex = inputLine.indexOf(">", inputLine.indexOf("class=\"path\""));
              path = inputLine.substring(pathIndex + 1, inputLine.indexOf("<", pathIndex));
              rval.put(path, new Diff(path, new Checksum(path, isDir, length, csum), null));
          }
      }
      in.close();
      return rval;
  }
  static public class Diff implements Comparable<Diff> {
      public String path;
      public Checksum left;
      public Checksum right;
      public Diff(String path, Checksum left, Checksum right) {
          this.path = path;
          this.left = left;
          this.right = right;
      }
      public int compareTo(Diff that) {
          return path.compareTo(((Diff)that).path);
      }
      public String getCode() {
          if (left != null && right == null) return "missing";
          if (right != null && left == null) return "new";
          return left.md5.equals(right.md5) ? "" : "changed";
      }
  }

  static public class Checksum {
      public String path;
      public Boolean isDir;
      public Long length;
      public String md5;
      public Checksum(String path, Boolean isDir, Long length, String md5) {
          this.path = path;
          this.isDir = isDir;
          this.length = length;
          this.md5 = md5;
      }
  }

  static public class Md5Hasher {
      private File baseDir;
      private Set<File> ignored = new HashSet<File>();
      private Map<File,Checksum> cache = new TreeMap<File,Checksum>();
      private MessageDigest md;
      public Md5Hasher(File baseDir) throws Exception {
          this.baseDir = baseDir;
          this.md = MessageDigest.getInstance("MD5");
      }
      public Checksum getChecksum(File file) throws Exception {
          if (cache.containsKey(file)) return cache.get(file);
          if (!file.exists()) return null;
          Checksum checksum = null;
          if (file.isDirectory()) {
              long length = 0;
              StringBuilder sb = new StringBuilder("dir:");
              File[] children = file.listFiles();
              if (children != null) {
                  Arrays.sort(children);
                  for (File child : children) {
                      if (!ignored.contains(child.getAbsoluteFile())) {
                          Checksum childChecksum = getChecksum(child);
                          sb.append(child.getName()).append('=').append(childChecksum.md5).append(':');
                          length += childChecksum.length;
                      }
                  }
              }
              checksum = new Checksum(relDir(baseDir, file), file.isDirectory(), length, getChecksum(new ByteArrayInputStream(sb.toString().getBytes())));
          } else {
              checksum = new Checksum(relDir(baseDir, file), file.isDirectory(), file.length(), getChecksum(new BufferedInputStream(new FileInputStream(file))));
          }
          cache.put(file, checksum);
          return checksum;
      }
      private byte[] buffer = new byte[4096];
      private String getChecksum(InputStream in) throws Exception {
        md.reset();
        int bytesRead = 0;
        while ((bytesRead = in.read(buffer)) > 0) {
            md.update(buffer, 0, bytesRead);
        }
        in.close();
        return toHex(md.digest());
      }
      public void ignore(File f) { ignored.add(f); }
      public Map<File,Checksum> getResults() { return cache; }
  }

  static public String relDir(File baseDir, File child) {
      String basePath = fixPath(baseDir.getAbsolutePath());
      String childPath = fixPath(child.getAbsolutePath());
      return fixPath(childPath.equals(basePath) ? "." : ((childPath.startsWith(basePath) ? childPath.substring(basePath.length() + 1) : child.getAbsolutePath()).replaceAll("\\\\", "/")));
  }

  static public Map<String,Diff> diff(File baseDir, Map<String,Diff> target, Map<File,Checksum> current) {
      Map<String,Diff> rval = new TreeMap<String,Diff>();
      if (target != null) {
        for (String path : target.keySet()) {
            rval.put(path, target.get(path));
        }
      }
      for (File file : current.keySet()) {
          String path = relDir(baseDir, file);
          Diff d = rval.get(path);
          Checksum cs = current.get(file);
          if (d == null) rval.put(path, new Diff(path, null, cs));
          else d.right = cs;
      }
      return rval;
  }
  static public class Md5Properties {
      public Set<File> ignoredFiles = new HashSet<File>();
      public boolean isSecure = false;
      public Set<String> users = new HashSet<String>();
  }
  static public void applyProperties(Md5Properties rval, Properties p, File dir) {
      // *** process ignore paths
      String ignorePaths = p.getProperty("ignore");
      if (ignorePaths != null) {
          String[] splitPaths = ignorePaths.split(",");
          if (splitPaths != null) {
              for (String pathEl : splitPaths) {
                  if (pathEl != null && pathEl.trim().length() > 0) {
                      File file = dir == null ? new File(pathEl.trim()) : new File(dir, pathEl.trim());
                      System.out.println(file);
                      if (file.isAbsolute()) rval.ignoredFiles.add(file);
                  }
              }
           }
      }
      // *** process security
      if (!rval.isSecure) rval.isSecure = "true".equals(p.getProperty("secure"));
      String users = p.getProperty("users");
      if (users != null) {
          String[] splitUsers = users.split(",");
          if (splitUsers != null) {
              for (String userPass : splitUsers) {
                  if (isNotBlank(userPass)) {
                      rval.users.add(userPass.trim());
                  }
              }
          }
      }
  }
  static public Md5Properties loadProperties(HttpServletRequest request) {
      Md5Properties rval = new Md5Properties();
      // *** go up the directory tree, loading each md5.properties as you find it
      File dir = new File(request.getRealPath(request.getServletPath())).getAbsoluteFile().getParentFile();
      while (dir != null) {
          File propFile = new File(dir, "md5.properties").getAbsoluteFile();
          if (propFile.exists()) {
              try {
                  Properties p = new Properties();
                  p.load(new FileInputStream(propFile));
                  applyProperties(rval, p, dir);
              } catch(Exception ex) {
                  ex.printStackTrace();
              }
          }
          dir = dir.getParentFile();
      }
      // *** also load a central file from the user dir
      try {
          File userProps = new File(System.getProperty("user.home"), ".war-compare/md5.properties");
          if (userProps.exists()) {
              Properties p = new Properties();
              p.load(new FileInputStream(userProps));
              applyProperties(rval, p, null);
          } else {
              System.out.println("user file no exist");
              }
      } catch(Exception ex) { ex.printStackTrace(); }
      if (rval.users.size() == 0) rval.users.add("md5:md5pass");
      return rval;
  }
  static private boolean isBlank(String v) { return v == null || v.trim().length() == 0; }
  static private boolean isNotBlank(String v) { return !isBlank(v); }
  static private String fixPath(String p) {
      if (isBlank(p)) return ".";
      p = p.replaceAll("\\\\", "/");
      if (p.startsWith("/")) p = p.substring(1);
      if (p.startsWith("./")) p = p.substring(2);
      if (p.endsWith("/.")) p = p.substring(0, p.length() - 2);
      if (isBlank(p)) p = ".";
      return p;
  }
%>
<%
  System.out.println("md5.jsp");
  Enumeration en = request.getHeaderNames();
  while (en.hasMoreElements()) {
      String header = (String)en.nextElement();
      System.out.println(header + ": " + request.getHeader(header));
  }


  Md5Properties props = loadProperties(request);
  String userPass = null;
  if (props.isSecure) {
      String authorization = request.getHeader("Authorization");
      if (authorization == null) {
          response.setStatus(401);
          response.setHeader("WWW-Authenticate", "Basic realm=\"Secure Area\"");
          Writer w = response.getWriter();
          w.write("<html><body><h1>401 Unauthorized</h1></body></html>");
          w.flush();
          w.close();
          return;
      } else {
          try {
              if (!authorization.startsWith("Basic ")) throw new Exception("Unsupported authentication");
              String encoded = authorization.substring("Basic ".length());
              String decoded = new String(new sun.misc.BASE64Decoder().decodeBuffer(encoded));
              if (!props.users.contains(decoded)) throw new Exception(
                      "You do not have permission to access this resource. Add your username:password to the users property of md5.properties to gain access."
                      );
              userPass = decoded;
          } catch(Exception ex) {
              response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//              response.setHeader("WWW-Authenticate", "Basic realm=\"Secure Area\"");
              Writer w = response.getWriter();
              w.write("<html><body><h1>403 Forbidden</h1><p>" + ex.getMessage() + "</p></body></html>");
              w.flush();
              w.close();
              return;
          }
      }
  }

  //File webAppRootDir = new File(request.getRealPath(".")).getParentFile().getAbsoluteFile();
  File md5JspRootDir = new File(request.getRealPath(request.getServletPath())).getParentFile().getAbsoluteFile();

  String path = fixPath(request.getParameter("path"));
  if (path.contains("..")) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "For security reasons, '..' is forbidden in path.");
      return;
  }
  File scanFile = path.equals(".") ? md5JspRootDir : new File(md5JspRootDir, path);
  File scanBaseFile = null;

  Map<String,Diff> target = null;
  String compareTo = request.getParameter("compareTo");
  if (isBlank(compareTo)) compareTo = null;
  String compareToPath = null;
  String compareToBase = null;
  if (isNotBlank(compareTo)) {
      compareToPath = request.getParameter("compareToPath");
      compareToPath = isBlank(compareToPath) ? path : fixPath(compareToPath);
      if (path.contains("..")) {
          response.sendError(HttpServletResponse.SC_BAD_REQUEST, "For security reasons, '..' is forbidden in path.");
          return;
      }
      File leftFile = scanFile;
      File rightFile = new File(compareToPath);
      while (leftFile != null && rightFile != null && leftFile.getName().equals(rightFile.getName())) {
          leftFile = leftFile.getParentFile();
          rightFile = rightFile.getParentFile();
      }
      scanBaseFile = leftFile == null ? md5JspRootDir : leftFile;
      compareToBase = rightFile == null ? "." : rightFile.getPath();
      target = parseTarget(userPass, compareTo, compareToBase, compareToPath);
  } else {
      String base = fixPath(request.getParameter("base"));
      scanBaseFile = base.equals(".") ? md5JspRootDir : new File(md5JspRootDir, base);
  }
  String relPath = relDir(scanBaseFile, scanFile);

  Md5Hasher hasher = new Md5Hasher(scanBaseFile);
  for (File fileToIgnore : props.ignoredFiles) {
      hasher.ignore(fileToIgnore);
  }
  hasher.getChecksum(scanFile);
  File firstFile = scanFile;
  while (!firstFile.equals(scanBaseFile)) {
      firstFile = firstFile.getParentFile();
      hasher.getResults().put(firstFile, new Checksum(relDir(scanBaseFile, firstFile), true, 0L, ""));
  }

  Map<String,Diff> diffs = diff(scanBaseFile, target, hasher.getResults());
%>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
        <title>MD5 Report : <%=scanBaseFile%></title>
        <style type="text/css">
            table {  font-size: 12px; font-family: Consolas, "Courier New"; }
            .thead td { font-size: 16px; border-top: 5px solid black; font-weight: bold; }
            .tsub td { font-size: 10px; border-bottom: 5px solid black; }
            .footer td { border-top: 2px solid black; padding-top: 12px; }
            td { white-space: nowrap; padding-right: 16px; }
            .r0 { background-color: #DDDDDD; }
            .r1 { background-color: #EEEEEE; }
            .d_new { color: blue; }
            .d_missing { color: blue; }
            .d_changed { color: red; }
            .isDir, .path { display:none; }
        </style>
    </head>
    <body>
        <form action="md5.jsp">
        <table border="0" cellspacing="0">
            <tbody>
                <tr class="thead">
                    <td>Name</td>
                    <td>Size</td>
                    <td>MD5</td>
                    <% if (target != null) { %>
                    <td>Name</td>
                    <td>Size</td>
                    <td>MD5</td>
                    <% } else { %>
                    <td colspan="3">&nbsp;</td>
                    <% } %>
                </tr>
                <tr class="tsub">
                    <td colspan="3">
                        <%=request.getRequestURL()%> -&gt;
                        <%=path%>
                        <%--<%=basePath==null?"":basePath%><%=_path != null ? (basePath==null?_path:"/" + _path) : ""%>--%>
                    </td>
                    <td colspan="3">
                    <% if (target != null) { %>
                        <%=compareTo%> -&gt;
                        <%=compareToPath%>
                        <%--<%=targetBase==null?"":targetBase%><%=_path != null ? (targetBase==null?_path:"/" + _path) : ""%>--%>
                    <% } %>&nbsp;
                    </td>
                </tr>
                <%
                int row = 0;
                int pathDepth = (".".equals(relPath) || null == relPath) ? 0 : (relPath.startsWith("/") ? (relPath.split("/").length - 1) : (relPath.split("/").length));
                for (String diffPath : diffs.keySet()) {
                  Diff diff = diffs.get(diffPath);
                  int depth = ".".equals(diff.path) ? 0 : diff.path.split("/").length;
                  if (depth > pathDepth + 1) continue;
                  String fileName = diff.path.substring(diff.path.lastIndexOf("/") + 1);
                  String href = new StringBuilder(request.getRequestURL()).append("?")
                          .append("path=").append(relDir(md5JspRootDir, new File(scanBaseFile, diff.path)))
                          .append(compareTo == null ? "" : "&compareTo=" + compareTo)
                          .append(compareTo == null ? "" : "&compareToPath=" + relDir(new File("."), new File(compareToBase, diff.path)))
                          .toString();
//                          + (diff.path.equals(".") ? "" : "&path=" + diff.path) + (basePath==null?"":"&base="+basePath) + (targetUrl==null?"":"&target=" + targetUrl) + (targetBase == null?"":"&targetBase="+targetBase);
                %>
                <tr class="r<%=row%2%> d_<%=target==null?"":diff.getCode()%>" onclick="window.location='<%=href%>'">
                    <% if (diff.right != null) { %>
                    <td><% for (int i=0;i<depth*4;i++) {out.write("&nbsp;");}%>&nbsp;&nbsp;|--
                        <span style="<%=diff.right.isDir?"font-weight:bold;":""%>"><%=fileName%><%=!diff.right.path.equals(".") && diff.right.isDir?"/":""%></span><span class="isDir"><%=diff.right.isDir%></span>
                    </td>
                    <td class="len"><%=diff.right.length%></td>
                    <td><span class="csum"><%=diff.right.md5==null?"":diff.right.md5%></span><span class="path"><%=diff.path%></span></td>
                    <% } else { %>
                    <td colspan="3">&nbsp;</td>
                    <% } %>
                    <%
                    if (target != null && diff.left != null) {
                    %>
                            <td><% for (int i=0;i<depth*4;i++) {out.write("&nbsp;");}%>&nbsp;&nbsp;|--
                                <span style="<%=diff.left.isDir?"font-weight:bold;":""%>"><%=fileName%><%=!diff.left.path.equals(".") && diff.left.isDir?"/":""%></span>
                            </td>
                            <td><%=diff.left.length%></td>
                            <td><%=diff.left.md5%></td>
                    <%
                    } else {
                        %>
                        <td colspan="3">&nbsp;</td>
                        <%
                    }
                    %>
                </tr>
                <%
                  row++;
                }
                %>
                <tr class="footer">
                    <td colspan="3" valign="top">
                        Left JSP: &nbsp;<%=request.getRequestURL()%><%--<input size="40" value="<%=request.getRequestURL()%>" />--%><br />
                        Left Path: <input size="40" name="path" value="<%=path == null ? "" : path%>" /><br />
                        <input type="submit" />
                    </td>
                    <td colspan="3" valign="top">
                        Right JSP: &nbsp;<input size="40" name="compareTo" value="<%=compareTo == null ? "" : compareTo%>" /><br />
                        Right Path: <input size="40" name="compareToPath" value="<%=compareToPath == null || compareToPath.equals(path) ? "" : compareToPath%>" /><br />
                    </td>
                </tr>
            </tbody>
        </table>
        </form>
    </body>
</html>
