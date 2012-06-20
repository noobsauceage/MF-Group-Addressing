package edu.umass.cs.gcrs.server;

import edu.umass.cs.gcrs.gcrs.GCRS;
import edu.umass.cs.gcrs.utilities.Utils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 *
 * @author westy
 */
public class Server implements Runnable {

  private int port;

  public Server(int port) {
    this.port = port;
  }

  @Override
  public synchronized void run() {
    int i = 0;
    while (true) {
      ServerSocket serverSocket = null;
      Socket clientSocket;
      //Protocol protocol = new Protocol();
      try {
        GCRS.getLogger().info("Listening for input on port " + port);
        serverSocket = new ServerSocket(port);
        while (true) {
          clientSocket = serverSocket.accept();
          GCRS.getLogger().info("Server accepted connection " + i++ + " from " + clientSocket);
          new ProtocolThread(clientSocket).start();
        }
      } catch (SocketException se) {
        GCRS.getLogger().warning("SocketException: " + se);
        se.printStackTrace();
      } catch (Exception e) {
        GCRS.getLogger().warning("Caught the exception below and restarting in 2 seconds");
        logStackTrace(e);
        // add delay, may be things get better
        Utils.sleep(2000);
      }
      try {
        serverSocket.close();
      } catch (Exception e) {
      }
      Utils.sleep(2000); // just in case we're getting continous errors... don't grind to a halt
    }
  }

  private static void logStackTrace(Exception e) {
    StringBuilder result = new StringBuilder();
    final String NEW_LINE = System.getProperty("line.separator");
    result.append("Exception: " + e);
    result.append(NEW_LINE);
    for (StackTraceElement element : e.getStackTrace()) {
      result.append(element.getFileName() + ":");
      result.append(element.getLineNumber() + " ==> ");
      result.append(element.getMethodName() + "()");
      result.append(NEW_LINE);
    }
    GCRS.getLogger().warning(result.toString().trim());
  }
}