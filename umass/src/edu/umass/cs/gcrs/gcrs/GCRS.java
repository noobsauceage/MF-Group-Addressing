package edu.umass.cs.gcrs.gcrs;

import edu.umass.cs.gcrs.database.AclTable;
import edu.umass.cs.gcrs.database.GroupTable;
import edu.umass.cs.gcrs.database.MainTable;
import edu.umass.cs.gcrs.server.GcrsHttpServer;
import edu.umass.cs.gcrs.server.Server;
import edu.umass.cs.gcrs.utilities.Logging;
import java.io.File;
import java.util.logging.Logger;

/**
 *
 * @author westy
 */
public class GCRS {

  private final static Logger LOGGER = Logger.getLogger(GCRS.class.getName());
  public final static int SERVERPORT = 20001;

  public static Logger getLogger() {
    return LOGGER;
  }

  public static void init() {
    File dir = new File("log" + File.separatorChar);
    if (!dir.exists()) {
      dir.mkdirs();
    }
    Logging.setupLogger(LOGGER, "FINE", "log" + "/gcrs_log.xml");
//    MainTable.getInstance().maybeCreateTable();
//    AclTable.getInstance().maybeCreateTable();
//    GroupTable.getInstance().maybeCreateTable();
  }

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args) {
    GCRS.init();
    new Thread(new Server(SERVERPORT)).start();
    GcrsHttpServer.runServer();
  }
}
