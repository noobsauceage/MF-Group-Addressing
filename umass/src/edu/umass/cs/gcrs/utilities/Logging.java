/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.umass.cs.gcrs.utilities;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SocketHandler;

/**
 *
 * @author westy
 */
public class Logging {
  
  /**
     * Sets up the logger.
     *
     * @param	logLevel
     * @param	logFilename
     */
    public static void setupLogger(Logger logger, String logLevel, String logFilename) {
        Level level=null;
        try {
            level=Level.parse(logLevel);
        } catch(Exception e) {
            level=Level.FINE;
        }
	logger.setLevel(level);
	logger.setUseParentHandlers(false);
	
	try {
	    Handler ch = new ConsoleHandler();
	    ch.setLevel(level);
	    logger.addHandler(ch);
	} catch(Exception e) {
	    logger.warning("Unable to attach ConsoleHandler to logger!");
	    e.printStackTrace();
	}
	
	try {
	    Handler fh = new FileHandler(logFilename, 40000000, 45);
	    fh.setLevel(level);
	    logger.addHandler(fh);
	} catch(Exception e) {
	    logger.warning("Unable to attach FileHandler to logger!");
	    e.printStackTrace();
        }
    } 
  
}
