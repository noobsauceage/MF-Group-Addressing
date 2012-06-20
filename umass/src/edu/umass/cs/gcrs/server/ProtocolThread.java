/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.umass.cs.gcrs.server;

import edu.umass.cs.gcrs.gcrs.GCRS;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketException;

/**
 *
 * @author westy
 */
public class ProtocolThread extends Thread {

  private Socket clientSocket = null;

  public ProtocolThread(Socket socket) {
    super("ProtocolThread");
    this.clientSocket = socket;
  }

  @Override
  public void run() {

    try {
      Protocol protocol = new Protocol();
      PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
      BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
      String line;
      String outputLine;
      try {
        while ((line = in.readLine()) != null) {
          outputLine = protocol.processLineInput(line);
          if (outputLine != null) {
            GCRS.getLogger().finer("Response: " + outputLine);
            out.println(outputLine);
          } else {
            GCRS.getLogger().finer("NULL Response");
            out.println(Protocol.NULLRESPONSE);
          }
        }
      } catch (SocketException se) {
        GCRS.getLogger().severe("SocketException: " + se);
        se.printStackTrace();
      }
      in.close();
      out.close();
      clientSocket.close();

    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}