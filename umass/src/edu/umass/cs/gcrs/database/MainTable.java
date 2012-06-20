package edu.umass.cs.gcrs.database;

import edu.umass.cs.gcrs.gcrs.GCRS;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

/**
 * A frontend to the mySQL table which stores the fields and values
 * 
 * @author westy
 */
public class MainTable {

  public static String Version = "$Revision$";

  public MainTable() {
    MySQLUtils.maybeCreateTable(TableName, TableCreate);
  }

  // make it a singleton class
  public static MainTable getInstance() {
    return MainTableHolder.INSTANCE;
  }

  private static class MainTableHolder {

    private static final MainTable INSTANCE = new MainTable();
  }
  //public static final String PUBLICKEY = "publickey";
  public static final String GUID = "guid";
  public static final String JSON = "jsonobject";
  private static final String TableName = "main";
  private static final String TableCreate = "(id INT UNSIGNED NOT NULL AUTO_INCREMENT, PRIMARY KEY (id), " + GUID + " CHAR(40), " + JSON + " TEXT)";
  private static final String TableStandardQuery = "SELECT id, " + GUID + ", " + JSON + " FROM " + TableName;

  private String MainTableUpdate(String guid, JSONObject jsonObject) {
    return "SET " + GUID + " ='" + guid + "', " + JSON + " ='" + jsonObject.toString() + "'";
  }

  private MainTableEntry lookupHelper(String guid) {
    MainTableEntry result = null;
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = TableStandardQuery + " WHERE " + this.GUID + " = '" + guid + "'";
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeQuery(statement);

      ResultSet rs = s.getResultSet();
      if (rs.next()) {
        result = MainTableEntry.createFromResultSet(rs);
      }
      rs.close();
      s.close();
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
    return result;
  }

  public JSONObject lookup(String guid) {
    MainTableEntry entry = lookupHelper(guid);
    if (entry != null) {
      return entry.getJsonObject();
    }
    return null;
  }

  public String lookup(String guid, String key) {
    MainTableEntry entry = lookupHelper(guid);
    if (entry != null) {
      return (String) entry.getJsonObject().get(key);
    }
    return null;
  }

  public String dump() {
    StringBuilder result = new StringBuilder();
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = TableStandardQuery;
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeQuery(statement);
      ResultSet rs = s.getResultSet();
      while (rs.next()) {
        MainTableEntry entry = MainTableEntry.createFromResultSet(rs);
        JSONObject jsonObject = entry.getJsonObject();
        jsonObject.put("guid", entry.getGuid());
        result.append(jsonObject.toString());
        result.append("\n");
      }
      rs.close();
      s.close();
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
    if (result.length() > 0) { // trim newline
      result.setLength(result.length() - 1);
    }
    return result.toString().trim();
  }

  private JSONObject lookupJSONObject(String guid) {
    JSONObject jsonObject;
    MainTableEntry entry = lookupHelper(guid);
    if (entry == null) {
      return new JSONObject();
    } else {
      return entry.getJsonObject();
    }
  }

  // need to write test code for this
  public void updateFromObject(String guid, String value) {
    JSONObject jsonObject = lookupJSONObject(guid);
    jsonObject.putAll((JSONObject) JSONValue.parse(value));
    writeJSONObject(guid, jsonObject);
  }

  public void update(String guid, String key, String value) {
    JSONObject jsonObject = lookupJSONObject(guid);
    jsonObject.put(key, value);
    writeJSONObject(guid, jsonObject);
  }

  private void writeJSONObject(String guid, JSONObject jsonObject) {
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String setPart = MainTableUpdate(guid, jsonObject);
      String updateText = null;
      if (lookupHelper(guid) == null) { // redundant db access... live with it
        updateText = "INSERT INTO " + TableName + " " + setPart;
      } else {
        updateText = "UPDATE " + TableName + " " + setPart + " WHERE " + this.GUID + " = '" + guid + "'";
      }
      GCRS.getLogger().finer("Update text:" + updateText);

      s.executeUpdate(updateText);
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
  }

  private void delete(String guid) {
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      String statement = "DELETE FROM " + TableName + " WHERE " + this.GUID + " = '" + guid + "'";
      GCRS.getLogger().finer("Statement:" + statement);
      s.executeUpdate(statement);
    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    }
  }

  public ArrayList<MainTableEntry> retrieveAllEntries() {
    ArrayList<MainTableEntry> result = new ArrayList<MainTableEntry>();
    try {
      Connection conn = Connect.getConnection();
      Statement s = conn.createStatement();
      ResultSet rs;
      int count;

      s.executeQuery(TableStandardQuery);
      rs = s.getResultSet();
      count = 0;
      while (rs.next()) {
        ++count;
        MainTableEntry entry = MainTableEntry.createFromResultSet(rs);
        GCRS.getLogger().finer(entry.toString());
        result.add(entry);
      }
      GCRS.getLogger().finer(count + " entries were retrieved");
      rs.close();
      s.close();

    } catch (SQLException e) {
      GCRS.getLogger().severe("Error... problem executing statement : " + e);
    } finally {
      Connect.closeConnection();
    }
    return result;
  }

  public void printAllEntries() {
    for (MainTableEntry entry : retrieveAllEntries()) {
      System.out.println(entry.toString());
    }
  }

  public void resetTable() {
    MySQLUtils.dropTable(TableName);
    MySQLUtils.maybeCreateTable(TableName, TableCreate);
  }
}
