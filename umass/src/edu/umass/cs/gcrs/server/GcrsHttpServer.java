package edu.umass.cs.gcrs.server;

/**
 *
 * @author westy
 */
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import edu.umass.cs.gcrs.database.AclTable;
import edu.umass.cs.gcrs.database.GroupTable;
import edu.umass.cs.gcrs.database.MainTable;
import edu.umass.cs.gcrs.gcrs.GCRS;
import java.net.URI;
import java.util.regex.Matcher;

/**
 *
 * @author westy
 */
public class GcrsHttpServer {
  
  public static String Version = "$Revision$";

  private static Protocol protocol = new Protocol();
  private static String GCRSPATH = "GCRS";
  public static int address = 80;
  public static int addressNoPriv = 8080;
  
  public static String hostName = "umassmobilityfirst.net";

  public static void runServer() {
    if(!tryPort(address)) {
      tryPort(addressNoPriv);
    }
  }
  
  public static boolean tryPort(int address) {
    try {
      InetSocketAddress addr = new InetSocketAddress(address);
      HttpServer server = HttpServer.create(addr, 0);
      
      server.createContext("/", new EchoHandler());
      server.createContext("/" + GCRSPATH, new DefaultHandler());
      server.setExecutor(Executors.newCachedThreadPool());
      server.start();
      GCRS.getLogger().info("HTTP server is listening on port " + address);
      return true;
    } catch (IOException e) {
      GCRS.getLogger().severe("HTTP server failed to start on port " + address + " due to " + e);
      return false;
    }
  }

  public static void main(String[] args) throws IOException {
    runServer();
  }

  private static class DefaultHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) {
      try {

        String requestMethod = exchange.getRequestMethod();
        if (requestMethod.equalsIgnoreCase("GET")) {
          Headers responseHeaders = exchange.getResponseHeaders();
          responseHeaders.set("Content-Type", "text/plain");
          exchange.sendResponseHeaders(200, 0);

          OutputStream responseBody = exchange.getResponseBody();

          URI uri = exchange.getRequestURI();
          String path = uri.getPath();
          String query = uri.getQuery() != null ? uri.getQuery() : ""; // stupidly it returns null for empty query

          String action = path.replaceFirst("/" + GCRSPATH + "/", "");

          String response;
          if (!action.isEmpty()) {
            GCRS.getLogger().fine("Action: " + action + " Query:" + query);
            response = protocol.processQuery(action, query);
          } else {
            response = Protocol.BADRESPONSE;
          }
          GCRS.getLogger().fine("Response: " + response);
          responseBody.write(response.getBytes());
          responseBody.close();
        }
      } catch (Exception e) {
        GCRS.getLogger().warning("Error: " + e);
        e.printStackTrace();
        try {
          OutputStream responseBody = exchange.getResponseBody();
          responseBody.write(Protocol.BADRESPONSE.getBytes());
          responseBody.close();
        } catch (Exception f) {
          // at this point screw it
        }
      }
    }
  }

// EXAMPLE THAT JUST RETURNS HEADERS SENT
  private static class EchoHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
      String requestMethod = exchange.getRequestMethod();
      if (requestMethod.equalsIgnoreCase("GET")) {
        Headers responseHeaders = exchange.getResponseHeaders();
        responseHeaders.set("Content-Type", "text/plain");
        exchange.sendResponseHeaders(200, 0);

        OutputStream responseBody = exchange.getResponseBody();
        Headers requestHeaders = exchange.getRequestHeaders();
        Set<String> keySet = requestHeaders.keySet();
        Iterator<String> iter = keySet.iterator();
        
        String serverVersionInfo = "Server Version: " + Version.replaceFirst(Matcher.quoteReplacement("$Revision:"), "").replaceFirst(Matcher.quoteReplacement("$"), "") + "\n";
        String protocolVersionInfo = "Protocol Version: " + Protocol.Version.replaceFirst(Matcher.quoteReplacement("$Revision:"), "").replaceFirst(Matcher.quoteReplacement("$"), "") + "\n";
        String databaseVersionInfo = "Database Version: " + MainTable.Version.replaceFirst(Matcher.quoteReplacement("$Revision:"), "").replaceFirst(Matcher.quoteReplacement("$"), "") + "\n";
        String aclVersionInfo = "ACL Version: " + AclTable.Version.replaceFirst(Matcher.quoteReplacement("$Revision:"), "").replaceFirst(Matcher.quoteReplacement("$"), "") + "\n";
        String groupsVersionInfo = "Groups Version: " + GroupTable.Version.replaceFirst(Matcher.quoteReplacement("$Revision:"), "").replaceFirst(Matcher.quoteReplacement("$"), "") + "\n\n";
        
        responseBody.write(serverVersionInfo.getBytes());
        responseBody.write(protocolVersionInfo.getBytes());
        responseBody.write(databaseVersionInfo.getBytes());
        responseBody.write(aclVersionInfo.getBytes());
        responseBody.write(groupsVersionInfo.getBytes());
        while (iter.hasNext()) {
          String key = iter.next();
          List values = requestHeaders.get(key);
          String s = key + " = " + values.toString() + "\n";
          responseBody.write(s.getBytes());
        }
        responseBody.close();
      }
    }
  }
}