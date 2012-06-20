package edu.umass.cs.gcrs.database;

import java.sql.Connection;
import java.sql.DriverManager;
import edu.umass.cs.gcrs.gcrs.GCRS;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Abstraction of a database lookup. 
 * @author westy
 */
public class Connect {

  private static final String local_db_ip = "127.0.0.1";
  private static final String local_db_user = "root";
  private static final String local_db_pass = "toorbar";
  // move these into properties
  private static final String remote_db_ip = "mysql.westy.org";
  private static final String remote_db_user = "mfroot";
  private static final String remote_db_pass = "toorbar";
  // the name of the database.
  private static final String local_db_name = "gcrs";
  private static final String remote_db_name = "gcrs";
  // each thread has it's own connection
  private static ThreadLocal<Connection> connection = new ThreadLocal<Connection>();

  /**
   * Returns a database connection.
   * @return 
   */
  public static Connection getConnection() {
    if (connection == null) { // not sure why this happens, but let's cover it...
      connection = new ThreadLocal<Connection>();
    }
    if (connection.get() == null) {
      try {
        String url = "jdbc:mysql://" + local_db_ip + "/" + local_db_name;
        Class.forName("com.mysql.jdbc.Driver").newInstance();
        connection.set(DriverManager.getConnection(url, local_db_user, local_db_pass));
        GCRS.getLogger().info("Local database connection established");
      } catch (Exception e) {
        GCRS.getLogger().severe("Error... Cannot connect to database server: " + e);
      }
    }
    if (connection.get() == null) {
      try {
        String url = "jdbc:mysql://" + remote_db_ip + "/" + remote_db_name;
        Class.forName("com.mysql.jdbc.Driver").newInstance();
        connection.set(DriverManager.getConnection(url, remote_db_user, remote_db_pass));
        GCRS.getLogger().info("Remote database connection established");
      } catch (Exception e) {
        GCRS.getLogger().severe("Error... Cannot connect to database server: " + e);
      }
    }
    return connection.get();
  }

  /**
   * Closes a database connection.
   */
  public static void closeConnection() {
    if (connection != null) {
      try {
        connection.get().close();
        connection = null;
        GCRS.getLogger().info("Database connection terminated");
      } catch (Exception e) { /* ignore close errors */ }
    }
  }

  public static void main(String[] args) {

    Connection conn = getConnection();
    closeConnection();
  }
}
